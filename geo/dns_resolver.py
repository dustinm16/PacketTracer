"""Hostname and domain resolution with caching."""

import socket
import threading
from typing import Optional, Dict, Tuple, Callable, List, TYPE_CHECKING
from collections import OrderedDict
from queue import Queue, Empty
from dataclasses import dataclass
import time

from config import DNS_CACHE_SIZE, DNS_CACHE_TTL, DNS_TIMEOUT

if TYPE_CHECKING:
    from db.repositories.dns_repo import DNSRepository

# Callback type: function that receives HostInfo
DNSCallback = Callable[["HostInfo"], None]


@dataclass
class HostInfo:
    """Hostname information for an IP."""
    ip: str
    hostname: Optional[str] = None  # Short hostname (first part)
    domain: Optional[str] = None    # Base domain (e.g., "example.com")
    fqdn: Optional[str] = None      # Full Qualified Domain Name
    resolved: bool = False
    timestamp: float = 0.0

    @property
    def short_hostname(self) -> str:
        """Get short hostname (first part before domain)."""
        if self.fqdn:
            return self.fqdn.split('.')[0]
        if self.hostname:
            return self.hostname.split('.')[0]
        return ""

    @property
    def is_expired(self) -> bool:
        """Check if the cache entry is expired."""
        return (time.time() - self.timestamp) > DNS_CACHE_TTL

    @property
    def display_name(self) -> str:
        """Get best display name - prefers FQDN."""
        return self.fqdn or self.hostname or self.domain or ""


class DNSResolver:
    """Asynchronous DNS resolver with caching."""

    def __init__(
        self,
        cache_size: int = DNS_CACHE_SIZE,
        timeout: float = DNS_TIMEOUT,
        dns_repo: Optional["DNSRepository"] = None
    ):
        self.cache_size = cache_size
        self.timeout = timeout
        self.dns_repo = dns_repo  # Optional database repository
        self._cache: OrderedDict[str, HostInfo] = OrderedDict()
        self._lock = threading.Lock()
        # Queue now holds (ip, callback) tuples
        self._pending: Queue[Tuple[str, Optional[DNSCallback]]] = Queue()
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        # Track pending callbacks by IP
        self._pending_callbacks: Dict[str, List[DNSCallback]] = {}

        # Statistics
        self.lookups = 0
        self.cache_hits = 0
        self.failures = 0

        # Set socket timeout for DNS lookups
        socket.setdefaulttimeout(timeout)

    def _resolve_sync(self, ip: str) -> HostInfo:
        """Perform synchronous DNS lookup."""
        self.lookups += 1
        try:
            fqdn, aliases, _ = socket.gethostbyaddr(ip)

            # FQDN is the full name from reverse DNS
            # e.g., "ec2-1-2-3-4.compute-1.amazonaws.com"

            parts = fqdn.split('.')

            # Short hostname is first part
            # e.g., "ec2-1-2-3-4"
            short_hostname = parts[0] if parts else fqdn

            # Extract base domain (last 2-3 parts)
            # e.g., "amazonaws.com"
            if len(parts) >= 2:
                # Handle TLDs like .co.uk, .com.au
                if len(parts) >= 3 and len(parts[-2]) <= 3:
                    domain = '.'.join(parts[-3:])
                else:
                    domain = '.'.join(parts[-2:])
            else:
                domain = fqdn

            return HostInfo(
                ip=ip,
                hostname=short_hostname,
                domain=domain,
                fqdn=fqdn,
                resolved=True,
                timestamp=time.time(),
            )
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            self.failures += 1
            return HostInfo(
                ip=ip,
                resolved=True,  # Mark as resolved even on failure to prevent retries
                timestamp=time.time(),
            )

    def resolve(self, ip: str) -> HostInfo:
        """Resolve IP to hostname synchronously."""
        # Check cache
        with self._lock:
            if ip in self._cache:
                info = self._cache[ip]
                if not info.is_expired:
                    self.cache_hits += 1
                    self._cache.move_to_end(ip)
                    return info

        # Perform lookup
        info = self._resolve_sync(ip)

        # Cache result
        with self._lock:
            self._cache[ip] = info
            self._cache.move_to_end(ip)
            # Evict if over capacity
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)

        return info

    def resolve_async(
        self,
        ip: str,
        callback: Optional[DNSCallback] = None
    ) -> None:
        """Queue IP for asynchronous resolution with optional callback.

        Args:
            ip: IP address to resolve
            callback: Optional function to call with HostInfo when resolved
        """
        # Check cache first - if already resolved, call callback immediately
        with self._lock:
            if ip in self._cache and not self._cache[ip].is_expired:
                info = self._cache[ip]
                if callback:
                    try:
                        callback(info)
                    except Exception:
                        pass
                return

        # Register callback if provided
        if callback:
            with self._lock:
                if ip not in self._pending_callbacks:
                    self._pending_callbacks[ip] = []
                self._pending_callbacks[ip].append(callback)

        # Queue for background resolution
        self._pending.put((ip, callback))

    def get_cached(self, ip: str) -> Optional[HostInfo]:
        """Get cached hostname info if available."""
        with self._lock:
            info = self._cache.get(ip)
            if info and not info.is_expired:
                return info
        return None

    def _worker(self) -> None:
        """Background worker for async resolution."""
        while not self._stop_event.is_set():
            try:
                item = self._pending.get(timeout=0.5)
                # Handle both old format (just ip) and new format (ip, callback)
                ip = item[0] if isinstance(item, tuple) else item

                # Check if already cached
                with self._lock:
                    if ip in self._cache and not self._cache[ip].is_expired:
                        continue

                # Resolve
                info = self._resolve_sync(ip)

                # Cache
                with self._lock:
                    self._cache[ip] = info
                    while len(self._cache) > self.cache_size:
                        self._cache.popitem(last=False)

                # Persist to database if available
                if self.dns_repo:
                    self.dns_repo.upsert_from_host_info(info)

                # Call all registered callbacks for this IP
                callbacks = []
                with self._lock:
                    if ip in self._pending_callbacks:
                        callbacks = self._pending_callbacks.pop(ip)

                for callback in callbacks:
                    try:
                        callback(info)
                    except Exception:
                        pass

            except Empty:
                continue
            except Exception:
                pass

    def start(self) -> None:
        """Start background resolver thread."""
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
            self._worker_thread = None

    def get_stats(self) -> Dict:
        """Get resolver statistics."""
        with self._lock:
            cache_size = len(self._cache)

        hit_rate = self.cache_hits / max(1, self.lookups)
        return {
            "cache_size": cache_size,
            "max_cache_size": self.cache_size,
            "lookups": self.lookups,
            "cache_hits": self.cache_hits,
            "hit_rate": hit_rate,
            "failures": self.failures,
        }

    def clear(self) -> None:
        """Clear the cache."""
        with self._lock:
            self._cache.clear()
        self.lookups = 0
        self.cache_hits = 0
        self.failures = 0
