"""IP ownership and WHOIS information lookup."""

import socket
import subprocess
import threading
import re
from typing import Optional, Dict
from collections import OrderedDict
from queue import Queue, Empty
from dataclasses import dataclass, field
import time


@dataclass
class OwnershipInfo:
    """Ownership information for an IP or network."""
    ip: str
    asn: str = ""
    as_name: str = ""
    org: str = ""
    isp: str = ""
    network: str = ""
    country: str = ""
    abuse_contact: str = ""
    timestamp: float = field(default_factory=time.time)
    resolved: bool = False

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.timestamp) > 3600  # 1 hour


class OwnershipResolver:
    """Resolves IP ownership using Team Cymru's IP-to-ASN service."""

    # Team Cymru DNS-based ASN lookup
    CYMRU_DNS = "origin.asn.cymru.com"
    CYMRU_ASN_DNS = "asn.cymru.com"

    def __init__(self, cache_size: int = 5000):
        self.cache_size = cache_size
        self._cache: OrderedDict[str, OwnershipInfo] = OrderedDict()
        self._lock = threading.Lock()
        self._pending: Queue[str] = Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Statistics
        self.lookups = 0
        self.cache_hits = 0

    def _reverse_ip(self, ip: str) -> str:
        """Reverse IP octets for DNS query."""
        parts = ip.split('.')
        return '.'.join(reversed(parts))

    def _lookup_cymru_dns(self, ip: str) -> Optional[OwnershipInfo]:
        """Lookup ASN info via Team Cymru DNS TXT records.

        Uses dig command for TXT record lookup since socket.gethostbyname_ex
        doesn't support TXT records.

        Returns format: "ASN | IP | Network | Country | Registry"
        """
        try:
            # Query format: reversed_ip.origin.asn.cymru.com
            reversed_ip = self._reverse_ip(ip)
            query = f"{reversed_ip}.{self.CYMRU_DNS}"

            # Use dig for TXT lookup (faster than WHOIS)
            result = subprocess.run(
                ["dig", "+short", "TXT", query],
                capture_output=True,
                text=True,
                timeout=3
            )

            if result.returncode != 0 or not result.stdout.strip():
                return None

            # Parse response: "ASN | IP | Network | Country | Registry"
            txt_response = result.stdout.strip().strip('"')
            parts = [p.strip() for p in txt_response.split('|')]

            if len(parts) < 3:
                return None

            info = OwnershipInfo(ip=ip, timestamp=time.time(), resolved=True)
            info.asn = f"AS{parts[0]}" if parts[0] else ""
            info.network = parts[2] if len(parts) > 2 else ""
            info.country = parts[3] if len(parts) > 3 else ""

            # Get AS name from secondary query
            if info.asn:
                asn_num = parts[0]
                as_query = f"AS{asn_num}.{self.CYMRU_ASN_DNS}"
                as_result = subprocess.run(
                    ["dig", "+short", "TXT", as_query],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if as_result.returncode == 0 and as_result.stdout.strip():
                    # Format: "ASN | Country | Registry | Date | Name"
                    as_txt = as_result.stdout.strip().strip('"')
                    as_parts = [p.strip() for p in as_txt.split('|')]
                    if len(as_parts) >= 5:
                        info.as_name = as_parts[4]

            return info

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            # dig not available or timeout
            return None

    def _parse_whois_line(self, line: str, info: OwnershipInfo) -> None:
        """Parse a line from WHOIS output."""
        line = line.strip()
        if not line or line.startswith('%') or line.startswith('#'):
            return

        if ':' in line:
            key, _, value = line.partition(':')
            key = key.strip().lower()
            value = value.strip()

            if key in ('origin', 'originas'):
                info.asn = value
            elif key in ('as-name', 'asname'):
                info.as_name = value
            elif key in ('org-name', 'orgname', 'organization'):
                info.org = value
            elif key in ('descr', 'description'):
                if not info.org:
                    info.org = value
            elif key in ('netname', 'network'):
                info.network = value
            elif key in ('country',):
                info.country = value
            elif key in ('abuse-mailbox', 'abuse-c'):
                info.abuse_contact = value

    def _whois_query(self, ip: str, server: str = "whois.arin.net") -> Optional[str]:
        """Perform WHOIS query."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server, 43))
            sock.send(f"{ip}\r\n".encode())

            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()

            return response.decode('utf-8', errors='ignore')
        except Exception:
            return None

    def _resolve_from_geo(self, ip: str, geo_info: Optional[Dict]) -> OwnershipInfo:
        """Create ownership info from geo resolver data."""
        info = OwnershipInfo(ip=ip, timestamp=time.time(), resolved=True)

        if geo_info:
            if hasattr(geo_info, 'isp'):
                info.isp = geo_info.isp or ""
                info.org = geo_info.org or ""
                info.as_number = geo_info.as_number or ""
                info.as_name = geo_info.as_name or ""
                info.country = geo_info.country_code or ""
            elif isinstance(geo_info, dict):
                info.isp = geo_info.get('isp', '')
                info.org = geo_info.get('org', '')
                as_field = geo_info.get('as', '')
                if as_field:
                    parts = as_field.split(' ', 1)
                    info.asn = parts[0] if parts else ''
                    info.as_name = parts[1] if len(parts) > 1 else ''
                info.country = geo_info.get('countryCode', '')

        return info

    def resolve(self, ip: str) -> OwnershipInfo:
        """Resolve ownership info for an IP."""
        # Check cache
        with self._lock:
            if ip in self._cache:
                info = self._cache[ip]
                if not info.is_expired:
                    self.cache_hits += 1
                    self._cache.move_to_end(ip)
                    return info

        self.lookups += 1

        # Try fast CYMRU DNS lookup first
        info = self._lookup_cymru_dns(ip)
        if info and info.asn:
            # Cache and return the result
            with self._lock:
                self._cache[ip] = info
                while len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)
            return info

        # Fall back to WHOIS query for more details
        info = OwnershipInfo(ip=ip)

        response = self._whois_query(ip)
        if response:
            for line in response.split('\n'):
                self._parse_whois_line(line, info)

            # Check for referral
            if 'ReferralServer' in response or 'refer:' in response.lower():
                # Parse referral server
                for line in response.split('\n'):
                    if 'ReferralServer' in line or 'refer:' in line.lower():
                        match = re.search(r'whois://([^\s/:]+)', line)
                        if not match:
                            match = re.search(r'refer:\s*([^\s]+)', line.lower())
                        if match:
                            referral_server = match.group(1)
                            referred_response = self._whois_query(ip, referral_server)
                            if referred_response:
                                for rline in referred_response.split('\n'):
                                    self._parse_whois_line(rline, info)
                            break

        info.resolved = True
        info.timestamp = time.time()

        # Cache result
        with self._lock:
            self._cache[ip] = info
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)

        return info

    def resolve_async(self, ip: str) -> None:
        """Queue IP for async resolution."""
        with self._lock:
            if ip in self._cache and not self._cache[ip].is_expired:
                return
        self._pending.put(ip)

    def get_cached(self, ip: str) -> Optional[OwnershipInfo]:
        """Get cached ownership info."""
        with self._lock:
            info = self._cache.get(ip)
            if info and not info.is_expired:
                return info
        return None

    def update_from_geo(self, ip: str, geo_info) -> OwnershipInfo:
        """Update ownership info from geo data (faster than WHOIS)."""
        info = self._resolve_from_geo(ip, geo_info)

        with self._lock:
            # Only cache if we don't have better data
            if ip not in self._cache or not self._cache[ip].asn:
                self._cache[ip] = info
                while len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)

        return info

    def _worker(self) -> None:
        """Background worker for async resolution."""
        while not self._stop_event.is_set():
            try:
                ip = self._pending.get(timeout=0.5)
                with self._lock:
                    if ip in self._cache and not self._cache[ip].is_expired:
                        continue

                self.resolve(ip)

            except Empty:
                continue
            except Exception:
                pass

    def start(self) -> None:
        """Start background resolver."""
        if self._worker_thread and self._worker_thread.is_alive():
            return
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._worker, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        """Stop background resolver."""
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=2)

    def get_stats(self) -> Dict:
        """Get resolver statistics."""
        with self._lock:
            size = len(self._cache)
        return {
            "cache_size": size,
            "lookups": self.lookups,
            "cache_hits": self.cache_hits,
        }
