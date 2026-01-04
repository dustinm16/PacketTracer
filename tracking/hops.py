"""Hop analysis from TTL values."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import threading

from config import DEFAULT_TTL


@dataclass
class HopInfo:
    """Information about estimated hops to a destination."""

    ip: str
    min_hops: int
    max_hops: int
    avg_hops: float
    sample_count: int
    likely_os: str
    initial_ttl: int


class HopAnalyzer:
    """Analyzes TTL values to estimate hop counts."""

    def __init__(self):
        self._ip_ttls: Dict[str, List[int]] = {}
        self._lock = threading.Lock()

    def record_ttl(self, ip: str, ttl: int) -> None:
        """Record a TTL value for an IP address."""
        with self._lock:
            if ip not in self._ip_ttls:
                self._ip_ttls[ip] = []
            self._ip_ttls[ip].append(ttl)
            # Keep only last 100 samples
            if len(self._ip_ttls[ip]) > 100:
                self._ip_ttls[ip] = self._ip_ttls[ip][-100:]

    def estimate_initial_ttl(self, ttl: int) -> Tuple[int, str]:
        """Estimate the initial TTL and likely OS from observed TTL."""
        if ttl <= 64:
            return 64, "linux/unix"
        elif ttl <= 128:
            return 128, "windows"
        else:
            return 255, "network_device"

    def get_hop_info(self, ip: str) -> Optional[HopInfo]:
        """Get hop information for an IP address."""
        with self._lock:
            ttls = self._ip_ttls.get(ip)
            if not ttls:
                return None

            min_ttl = min(ttls)
            max_ttl = max(ttls)
            avg_ttl = sum(ttls) / len(ttls)

            initial_ttl, likely_os = self.estimate_initial_ttl(min_ttl)

            min_hops = initial_ttl - max_ttl
            max_hops = initial_ttl - min_ttl
            avg_hops = initial_ttl - avg_ttl

            return HopInfo(
                ip=ip,
                min_hops=max(0, min_hops),
                max_hops=max(0, max_hops),
                avg_hops=max(0, avg_hops),
                sample_count=len(ttls),
                likely_os=likely_os,
                initial_ttl=initial_ttl,
            )

    def get_all_hop_info(self) -> List[HopInfo]:
        """Get hop info for all tracked IPs."""
        with self._lock:
            ips = list(self._ip_ttls.keys())

        results = []
        for ip in ips:
            info = self.get_hop_info(ip)
            if info:
                results.append(info)

        return results

    def get_ips_by_hops(self, min_hops: int, max_hops: int) -> List[str]:
        """Get IPs within a hop range."""
        all_info = self.get_all_hop_info()
        return [
            info.ip
            for info in all_info
            if min_hops <= info.avg_hops <= max_hops
        ]

    def clear(self) -> None:
        """Clear all recorded data."""
        with self._lock:
            self._ip_ttls.clear()
