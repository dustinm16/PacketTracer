"""Database-backed port tracker with compatible interface."""

import time
import threading
from typing import Dict, List, Tuple, Optional, Set, TYPE_CHECKING
from collections import defaultdict

from .ports import PortStats, ScanActivity, KNOWN_SERVICES

if TYPE_CHECKING:
    from db.repositories.port_repo import PortRepository, PortRecord


class DBPortTracker:
    """Database-backed port tracker with interface compatible with PortTracker.

    This class provides the same interface as PortTracker but stores data
    in SQLite via the PortRepository. It maintains in-memory buffers for
    real-time hit counting and scan detection.
    """

    def __init__(
        self,
        port_repo: "PortRepository",
        max_ports: int = 1000,
        scan_window: int = 60
    ):
        self.port_repo = port_repo
        self.max_ports = max_ports
        self.scan_window = scan_window
        self._lock = threading.Lock()

        # In-memory accumulator for batching
        self._pending: Dict[Tuple[int, str], dict] = {}

        # Hit tracking (needs to be in-memory for uniqueness)
        self._port_hits: Dict[Tuple[int, str], Set[str]] = defaultdict(set)

        # Scan detection (needs real-time tracking)
        self._scan_activity: Dict[str, ScanActivity] = {}

        # Time-series for recent activity (last 60 seconds)
        self._port_history: Dict[Tuple[int, str], List[int]] = defaultdict(lambda: [0] * 60)
        self._last_second: int = 0

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

                # Initialize pending if new
                if key not in self._pending:
                    self._pending[key] = {
                        "port": port,
                        "protocol": protocol,
                        "packets_in": 0,
                        "packets_out": 0,
                        "bytes_in": 0,
                        "bytes_out": 0,
                        "hit_count": 0,
                        "unique_sources": 0,
                        "unique_destinations": 0,
                        "first_seen": now,
                        "last_seen": now,
                        "_src_ips": set(),
                        "_dst_ips": set(),
                    }

                pending = self._pending[key]
                pending["last_seen"] = now

                if is_dst:
                    pending["packets_in"] += 1
                    pending["bytes_in"] += length
                    pending["_dst_ips"].add(dst_ip)
                    pending["_src_ips"].add(src_ip)

                    # Track hit count (unique source IPs hitting this port)
                    if src_ip not in self._port_hits[key]:
                        self._port_hits[key].add(src_ip)
                        pending["hit_count"] = len(self._port_hits[key])
                else:
                    pending["packets_out"] += 1
                    pending["bytes_out"] += length
                    pending["_src_ips"].add(src_ip)

                # Update unique counts
                pending["unique_sources"] = len(pending["_src_ips"])
                pending["unique_destinations"] = len(pending["_dst_ips"])

                # Update time series
                current_second = int(now) % 60
                if current_second != self._last_second:
                    steps = (current_second - self._last_second) % 60
                    for i in range(steps):
                        idx = (self._last_second + i + 1) % 60
                        for k in self._port_history:
                            self._port_history[k][idx] = 0
                    self._last_second = current_second

                self._port_history[key][current_second] += 1

                # Queue to database (without internal tracking sets)
                db_data = {k: v for k, v in pending.items() if not k.startswith("_")}
                self.port_repo.record_port_activity(**db_data)

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

    def get_top_ports(self, n: int = 20, by: str = "bytes") -> List[PortStats]:
        """Get top N ports by traffic metric."""
        records = self.port_repo.get_top_ports(limit=n, sort_by=by)
        return [self._record_to_stats(r) for r in records]

    def get_port_stats(self, port: int, protocol: str = "TCP") -> Optional[PortStats]:
        """Get stats for a specific port."""
        record = self.port_repo.get_port_stats(port, protocol)
        if record:
            return self._record_to_stats(record)
        return None

    def get_service_name(self, port: int) -> Tuple[str, str]:
        """Get service name and description for a port."""
        return KNOWN_SERVICES.get(port, ("Unknown", ""))

    def get_port_history(self, port: int, protocol: str = "TCP") -> List[int]:
        """Get packet count history for a port (last 60 seconds)."""
        with self._lock:
            return list(self._port_history.get((port, protocol), [0] * 60))

    def get_active_ports(self, seconds: int = 60) -> List[PortStats]:
        """Get ports active within the last N seconds."""
        # Use in-memory pending data for real-time
        cutoff = time.time() - seconds
        with self._lock:
            active = []
            for key, data in self._pending.items():
                if data["last_seen"] > cutoff:
                    active.append(self._pending_to_stats(key, data))
            return active

    def get_summary(self) -> Dict:
        """Get summary statistics."""
        with self._lock:
            total_ports = len(self._pending)
            total_bytes = sum(d["bytes_in"] + d["bytes_out"] for d in self._pending.values())
            total_packets = sum(d["packets_in"] + d["packets_out"] for d in self._pending.values())

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
        records = self.port_repo.get_top_ports(limit=n, sort_by="hits")
        return [self._record_to_stats(r) for r in records]

    def get_port_range_stats(self) -> Dict[str, Dict]:
        """Get statistics by port range."""
        return self.port_repo.get_port_range_stats()

    def get_service_breakdown(self) -> List[Dict]:
        """Get traffic grouped by common services."""
        return self.port_repo.get_service_breakdown()

    def clear(self) -> None:
        """Clear all in-memory tracking data."""
        with self._lock:
            self._pending.clear()
            self._port_history.clear()
            self._scan_activity.clear()
            self._port_hits.clear()

    def _record_to_stats(self, record: "PortRecord") -> PortStats:
        """Convert PortRecord to PortStats for compatibility."""
        return PortStats(
            port=record.port,
            protocol=record.protocol,
            packets_in=record.packets_in,
            packets_out=record.packets_out,
            bytes_in=record.bytes_in,
            bytes_out=record.bytes_out,
            connections=record.unique_sources,
            first_seen=record.first_seen,
            last_seen=record.last_seen,
            hit_count=record.hit_count,
            src_ips=set(),  # Not tracked in DB
            dst_ips=set(),
        )

    def _pending_to_stats(self, key: Tuple[int, str], data: dict) -> PortStats:
        """Convert pending data to PortStats."""
        return PortStats(
            port=data["port"],
            protocol=data["protocol"],
            packets_in=data["packets_in"],
            packets_out=data["packets_out"],
            bytes_in=data["bytes_in"],
            bytes_out=data["bytes_out"],
            connections=data["unique_sources"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            hit_count=data["hit_count"],
            src_ips=data.get("_src_ips", set()),
            dst_ips=data.get("_dst_ips", set()),
        )
