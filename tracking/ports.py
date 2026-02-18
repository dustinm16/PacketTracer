"""Port transit tracking - monitor traffic by port."""

import threading
import time
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class PortStats:
    """Statistics for a single port."""
    port: int
    protocol: str = "TCP"
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    connections: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Hit count - unique connection attempts (src_ip -> port)
    hit_count: int = 0

    # Track unique IPs
    src_ips: set = field(default_factory=set)
    dst_ips: set = field(default_factory=set)

    @property
    def total_packets(self) -> int:
        return self.packets_in + self.packets_out

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out

    @property
    def unique_sources(self) -> int:
        return len(self.src_ips)

    @property
    def unique_destinations(self) -> int:
        return len(self.dst_ips)

    @property
    def activity_duration(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def packets_per_second(self) -> float:
        duration = max(1, self.activity_duration)
        return self.total_packets / duration

    @property
    def bytes_per_second(self) -> float:
        duration = max(1, self.activity_duration)
        return self.total_bytes / duration


@dataclass
class ScanActivity:
    """Tracks potential port scanning activity from a source IP."""
    src_ip: str
    ports_hit: Set[int] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0

    @property
    def unique_ports(self) -> int:
        return len(self.ports_hit)

    @property
    def scan_rate(self) -> float:
        """Ports per second scan rate."""
        duration = max(1, self.last_seen - self.first_seen)
        return self.unique_ports / duration

    @property
    def is_likely_scan(self) -> bool:
        """Heuristic: scanning if >10 unique ports in rapid succession."""
        return self.unique_ports > 10 and self.scan_rate > 0.5


# Well-known port to service mappings
KNOWN_SERVICES = {
    20: ("FTP-Data", "File Transfer"),
    21: ("FTP", "File Transfer"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Remote Access"),
    25: ("SMTP", "Email Sending"),
    53: ("DNS", "Domain Resolution"),
    67: ("DHCP-S", "DHCP Server"),
    68: ("DHCP-C", "DHCP Client"),
    80: ("HTTP", "Web Traffic"),
    110: ("POP3", "Email Retrieval"),
    123: ("NTP", "Time Sync"),
    143: ("IMAP", "Email Access"),
    161: ("SNMP", "Monitoring"),
    443: ("HTTPS", "Secure Web"),
    445: ("SMB", "File Sharing"),
    465: ("SMTPS", "Secure Email"),
    514: ("Syslog", "Logging"),
    587: ("SMTP", "Email Submit"),
    993: ("IMAPS", "Secure Email"),
    995: ("POP3S", "Secure Email"),
    1433: ("MSSQL", "Database"),
    1521: ("Oracle", "Database"),
    3306: ("MySQL", "Database"),
    3389: ("RDP", "Remote Desktop"),
    5432: ("PostgreSQL", "Database"),
    5900: ("VNC", "Remote Desktop"),
    6379: ("Redis", "Cache/DB"),
    8080: ("HTTP-Alt", "Web Proxy"),
    8443: ("HTTPS-Alt", "Secure Web"),
    27017: ("MongoDB", "Database"),
}


class PortTracker:
    """Tracks network traffic by port."""

    def __init__(self, max_ports: int = 1000, scan_window: int = 60):
        self.max_ports = max_ports
        self.scan_window = scan_window  # Window in seconds for scan detection
        self._ports: Dict[Tuple[int, str], PortStats] = {}
        self._lock = threading.Lock()

        # Time-series data for top ports (last 60 seconds)
        self._port_history: Dict[Tuple[int, str], List[int]] = defaultdict(lambda: [0] * 60)
        self._last_second: int = 0

        # Scan detection: track ports hit by each source IP
        self._scan_activity: Dict[str, ScanActivity] = {}

        # Hit tracking: which src_ips have already hit each port (for hit_count)
        self._port_hits: Dict[Tuple[int, str], Set[str]] = defaultdict(set)

    def record_packet(
        self,
        src_port: int,
        dst_port: int,
        protocol: str,
        length: int,
        src_ip: str,
        dst_ip: str,
        is_outbound: bool = True,
    ) -> None:
        """Record a packet for port tracking."""
        with self._lock:
            now = time.time()

            # Track scan activity for the source IP hitting destination port
            if dst_port > 0:
                self._update_scan_activity(src_ip, dst_port, now)

            # Track both ports
            for port, is_dst in [(src_port, False), (dst_port, True)]:
                if port <= 0:
                    continue

                key = (port, protocol)

                if key not in self._ports:
                    self._ports[key] = PortStats(port=port, protocol=protocol)

                stats = self._ports[key]
                stats.last_seen = now

                if is_dst:
                    stats.packets_in += 1
                    stats.bytes_in += length
                    stats.dst_ips.add(dst_ip)
                    stats.src_ips.add(src_ip)

                    # Track hit count (unique source IPs hitting this port)
                    if src_ip not in self._port_hits[key]:
                        self._port_hits[key].add(src_ip)
                        stats.hit_count += 1
                else:
                    stats.packets_out += 1
                    stats.bytes_out += length
                    stats.src_ips.add(src_ip)

                # Update time series
                current_second = int(now) % 60
                if current_second != self._last_second:
                    # Clear old buckets
                    steps = (current_second - self._last_second) % 60
                    for i in range(steps):
                        idx = (self._last_second + i + 1) % 60
                        for k in self._port_history:
                            self._port_history[k][idx] = 0
                    self._last_second = current_second

                self._port_history[key][current_second] += 1

            # Prune if too many ports
            if len(self._ports) > self.max_ports:
                self._prune()

    def _update_scan_activity(self, src_ip: str, dst_port: int, now: float) -> None:
        """Update scan activity tracking for a source IP."""
        if src_ip not in self._scan_activity:
            self._scan_activity[src_ip] = ScanActivity(src_ip=src_ip)

        activity = self._scan_activity[src_ip]
        activity.last_seen = now
        activity.ports_hit.add(dst_port)
        activity.packet_count += 1

        # Clean up old scan activity outside the window
        cutoff = now - self.scan_window
        to_remove = [ip for ip, a in self._scan_activity.items() if a.last_seen < cutoff]
        for ip in to_remove:
            del self._scan_activity[ip]

    def _prune(self) -> None:
        """Remove least active ports."""
        # Sort by last_seen and remove oldest
        sorted_ports = sorted(
            self._ports.items(),
            key=lambda x: x[1].last_seen,
        )
        # Keep top 80%
        keep_count = int(self.max_ports * 0.8)
        remove_keys = [k for k, v in sorted_ports[:-keep_count]]
        for k in remove_keys:
            del self._ports[k]
            if k in self._port_history:
                del self._port_history[k]

    def get_top_ports(self, n: int = 20, by: str = "bytes") -> List[PortStats]:
        """Get top N ports by traffic metric."""
        with self._lock:
            ports = list(self._ports.values())

        if by == "bytes":
            ports.sort(key=lambda p: p.total_bytes, reverse=True)
        elif by == "packets":
            ports.sort(key=lambda p: p.total_packets, reverse=True)
        elif by == "connections":
            ports.sort(key=lambda p: p.unique_sources + p.unique_destinations, reverse=True)
        elif by == "rate":
            ports.sort(key=lambda p: p.packets_per_second, reverse=True)
        else:
            ports.sort(key=lambda p: p.total_bytes, reverse=True)

        return ports[:n]

    def get_port_stats(self, port: int, protocol: str = "TCP") -> Optional[PortStats]:
        """Get stats for a specific port."""
        with self._lock:
            return self._ports.get((port, protocol))

    def get_service_name(self, port: int) -> Tuple[str, str]:
        """Get service name and description for a port."""
        return KNOWN_SERVICES.get(port, ("Unknown", ""))

    def get_port_history(self, port: int, protocol: str = "TCP") -> List[int]:
        """Get packet count history for a port (last 60 seconds)."""
        with self._lock:
            return list(self._port_history.get((port, protocol), [0] * 60))

    def get_active_ports(self, seconds: int = 60) -> List[PortStats]:
        """Get ports active within the last N seconds."""
        cutoff = time.time() - seconds
        with self._lock:
            return [p for p in self._ports.values() if p.last_seen > cutoff]

    def get_summary(self) -> Dict:
        """Get summary statistics."""
        with self._lock:
            total_ports = len(self._ports)
            total_bytes = sum(p.total_bytes for p in self._ports.values())
            total_packets = sum(p.total_packets for p in self._ports.values())

        return {
            "total_ports": total_ports,
            "total_bytes": total_bytes,
            "total_packets": total_packets,
        }

    def get_scan_activity(self, min_ports: int = 5) -> List[ScanActivity]:
        """Get sources with scan-like activity (hitting many ports)."""
        with self._lock:
            activities = [
                a for a in self._scan_activity.values()
                if a.unique_ports >= min_ports
            ]
        activities.sort(key=lambda a: a.unique_ports, reverse=True)
        return activities

    def get_likely_scanners(self) -> List[ScanActivity]:
        """Get sources that are likely port scanning."""
        with self._lock:
            return [a for a in self._scan_activity.values() if a.is_likely_scan]

    def get_top_hit_ports(self, n: int = 10) -> List[PortStats]:
        """Get ports with highest hit counts (unique source IPs)."""
        with self._lock:
            ports = list(self._ports.values())
        ports.sort(key=lambda p: p.hit_count, reverse=True)
        return ports[:n]

    def clear(self) -> None:
        """Clear all tracking data."""
        with self._lock:
            self._ports.clear()
            self._port_history.clear()
            self._scan_activity.clear()
            self._port_hits.clear()
