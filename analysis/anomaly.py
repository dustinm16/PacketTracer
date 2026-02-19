"""Flow anomaly scoring — flags oddities in traffic patterns."""

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Deque
from collections import defaultdict, deque

from tracking.flow import Flow


@dataclass
class AnomalyScore:
    """Anomaly assessment for a single flow."""
    flow_key: str
    total_score: float = 0.0  # 0.0 (normal) to 1.0 (highly anomalous)
    reasons: List[str] = field(default_factory=list)

    # Individual signal scores (0.0–1.0 each)
    byte_ratio_score: float = 0.0
    duration_score: float = 0.0
    packet_size_score: float = 0.0
    ttl_variance_score: float = 0.0
    connection_rate_score: float = 0.0

    @property
    def is_anomalous(self) -> bool:
        """Considered anomalous if combined score exceeds threshold."""
        return self.total_score >= 0.5

    @property
    def severity(self) -> str:
        if self.total_score >= 0.8:
            return "critical"
        elif self.total_score >= 0.6:
            return "high"
        elif self.total_score >= 0.4:
            return "medium"
        elif self.total_score >= 0.2:
            return "low"
        return "info"


class FlowAnomalyDetector:
    """Scores flows for anomalous characteristics.

    Signals checked:
      1. Byte ratio asymmetry — heavy send vs receive imbalance
      2. Duration oddities — too short or too long for the protocol
      3. Packet size — average size far from typical for protocol
      4. TTL variance — multiple TTL values within a single flow
      5. Per-IP connection rate — sudden burst of new flows from one source
    """

    # Expected characteristics per well-known destination port
    PORT_PROFILES: Dict[int, Dict] = {
        # port: (typical ratio sent/recv, min_dur_s, max_dur_s, avg_pkt_size)
        22:   {"name": "SSH",   "ratio": 1.0,  "min_dur": 1,   "max_dur": 7200, "pkt_size": 200},
        53:   {"name": "DNS",   "ratio": 0.3,  "min_dur": 0,   "max_dur": 5,    "pkt_size": 100},
        80:   {"name": "HTTP",  "ratio": 0.15, "min_dur": 0,   "max_dur": 300,  "pkt_size": 800},
        443:  {"name": "HTTPS", "ratio": 0.2,  "min_dur": 0,   "max_dur": 600,  "pkt_size": 900},
        3306: {"name": "MySQL", "ratio": 0.4,  "min_dur": 0.5, "max_dur": 3600, "pkt_size": 300},
        3389: {"name": "RDP",   "ratio": 0.8,  "min_dur": 5,   "max_dur": 28800,"pkt_size": 600},
    }

    def __init__(self, connection_window: int = 60, connection_threshold: int = 30):
        self._lock = threading.Lock()
        # Per-IP connection timestamps (for rate anomaly)
        self._ip_connections: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=500))
        self._connection_window = connection_window  # seconds
        self._connection_threshold = connection_threshold  # flows/window
        # Cache scored results
        self._scores: Dict[str, AnomalyScore] = {}

    def score_flow(self, flow: Flow) -> AnomalyScore:
        """Compute anomaly score for a flow."""
        result = AnomalyScore(flow_key=flow.flow_key)

        result.byte_ratio_score = self._score_byte_ratio(flow, result)
        result.duration_score = self._score_duration(flow, result)
        result.packet_size_score = self._score_packet_size(flow, result)
        result.ttl_variance_score = self._score_ttl_variance(flow, result)
        result.connection_rate_score = self._score_connection_rate(flow, result)

        # Weighted combination — byte ratio and connection rate weighted higher
        weights = {
            "byte_ratio": 0.30,
            "duration": 0.15,
            "packet_size": 0.15,
            "ttl_variance": 0.15,
            "connection_rate": 0.25,
        }
        result.total_score = min(1.0, (
            result.byte_ratio_score * weights["byte_ratio"] +
            result.duration_score * weights["duration"] +
            result.packet_size_score * weights["packet_size"] +
            result.ttl_variance_score * weights["ttl_variance"] +
            result.connection_rate_score * weights["connection_rate"]
        ))

        with self._lock:
            self._scores[flow.flow_key] = result

        return result

    def record_connection(self, src_ip: str, timestamp: float) -> None:
        """Record a new connection for per-IP rate tracking."""
        with self._lock:
            self._ip_connections[src_ip].append(timestamp)

    def get_score(self, flow_key: str) -> Optional[AnomalyScore]:
        """Retrieve cached score for a flow."""
        with self._lock:
            return self._scores.get(flow_key)

    def get_anomalous_flows(self, min_score: float = 0.5) -> List[AnomalyScore]:
        """Get all flows above the anomaly threshold."""
        with self._lock:
            return sorted(
                [s for s in self._scores.values() if s.total_score >= min_score],
                key=lambda s: s.total_score,
                reverse=True,
            )

    def get_ip_connection_rate(self, ip: str) -> int:
        """Current connection count within the window for an IP."""
        cutoff = time.time() - self._connection_window
        with self._lock:
            times = self._ip_connections.get(ip)
            if not times:
                return 0
            return sum(1 for t in times if t > cutoff)

    # ------------------------------------------------------------------
    # Individual scoring methods
    # ------------------------------------------------------------------

    def _score_byte_ratio(self, flow: Flow, result: AnomalyScore) -> float:
        """Score byte send/receive asymmetry.

        Normal browsing: client sends little, receives lots (ratio ~0.1-0.3).
        Exfiltration: client sends much more than it receives (ratio >5).
        """
        if flow.total_bytes < 1000 or flow.total_packets < 5:
            return 0.0  # Not enough data to judge

        sent = max(flow.bytes_sent, 1)
        recv = max(flow.bytes_recv, 1)
        ratio = sent / recv

        # Compare against port profile if available
        profile = self.PORT_PROFILES.get(flow.dst_port)
        if profile:
            expected = profile["ratio"]
            deviation = abs(math.log2(max(ratio, 0.001)) - math.log2(max(expected, 0.001)))
            if deviation > 4:
                result.reasons.append(
                    f"byte_ratio: {ratio:.1f} (expected ~{expected:.1f} for {profile['name']})"
                )
                return min(1.0, deviation / 6.0)
            return min(1.0, deviation / 8.0)

        # No profile — flag extreme asymmetry
        if ratio > 10.0:
            result.reasons.append(f"byte_ratio: heavy upload ({ratio:.1f}x more sent than received)")
            return min(1.0, ratio / 20.0)
        if ratio < 0.01:
            # Extreme download with almost nothing sent — unusual unless streaming
            if flow.total_bytes > 10_000_000:  # >10 MB
                return 0.1  # Probably legitimate download
            result.reasons.append(f"byte_ratio: extreme download ({1/ratio:.0f}x more recv)")
            return 0.3
        return 0.0

    def _score_duration(self, flow: Flow, result: AnomalyScore) -> float:
        """Score flow duration against expected range for the port."""
        duration = flow.duration
        if duration < 0:
            duration = 0

        profile = self.PORT_PROFILES.get(flow.dst_port)
        if not profile:
            # No profile — only flag very long low-traffic flows ("zombie" connections)
            if duration > 3600 and flow.total_packets < 10:
                result.reasons.append(
                    f"duration: {duration:.0f}s with only {flow.total_packets} packets (zombie)"
                )
                return 0.7
            return 0.0

        if duration < profile["min_dur"] and flow.total_packets > 3:
            result.reasons.append(
                f"duration: {duration:.1f}s (too short for {profile['name']}, min {profile['min_dur']}s)"
            )
            return 0.5
        if duration > profile["max_dur"]:
            excess = duration / profile["max_dur"]
            result.reasons.append(
                f"duration: {duration:.0f}s (exceeds max {profile['max_dur']}s for {profile['name']})"
            )
            return min(1.0, 0.3 + 0.1 * excess)
        return 0.0

    def _score_packet_size(self, flow: Flow, result: AnomalyScore) -> float:
        """Score average packet size for oddities."""
        if flow.total_packets < 3:
            return 0.0

        avg_size = flow.total_bytes / flow.total_packets

        profile = self.PORT_PROFILES.get(flow.dst_port)
        if profile:
            expected = profile["pkt_size"]
            if expected > 0:
                deviation = abs(avg_size - expected) / expected
                if deviation > 3.0:
                    result.reasons.append(
                        f"pkt_size: avg {avg_size:.0f}B (expected ~{expected}B for {profile['name']})"
                    )
                    return min(1.0, deviation / 5.0)
                return min(0.3, deviation / 5.0)

        # Generic: flag very small packets on data ports (possible covert channel)
        if avg_size < 50 and flow.total_packets > 20 and flow.dst_port not in (53, 123):
            result.reasons.append(f"pkt_size: tiny avg {avg_size:.0f}B over {flow.total_packets} packets")
            return 0.5

        return 0.0

    def _score_ttl_variance(self, flow: Flow, result: AnomalyScore) -> float:
        """Score TTL variance — a stable path should have consistent TTL.

        Multiple distinct TTL values in a single flow may indicate:
        - Route flapping
        - Man-in-the-middle (packets injected with different TTL)
        - Multihomed/load-balanced origin
        """
        if not flow.ttl_values or len(flow.ttl_values) < 5:
            return 0.0

        distinct = len(set(flow.ttl_values))
        if distinct <= 1:
            return 0.0

        # 2 distinct values is common (e.g., slightly different for data vs ack)
        if distinct == 2:
            vals = sorted(set(flow.ttl_values))
            if abs(vals[0] - vals[1]) <= 2:
                return 0.0  # Adjacent values, normal jitter
            result.reasons.append(
                f"ttl_variance: 2 distinct TTLs {vals[0]}, {vals[1]} (possible route change)"
            )
            return 0.3

        # 3+ distinct values is suspicious
        result.reasons.append(f"ttl_variance: {distinct} distinct TTL values in flow")
        return min(1.0, distinct / 6.0)

    def _score_connection_rate(self, flow: Flow, result: AnomalyScore) -> float:
        """Score based on how many connections the source IP has opened recently."""
        rate = self.get_ip_connection_rate(flow.src_ip)
        if rate <= self._connection_threshold:
            return 0.0

        excess = rate / self._connection_threshold
        result.reasons.append(
            f"conn_rate: {rate} connections in {self._connection_window}s from {flow.src_ip}"
        )
        return min(1.0, excess / 5.0)

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def cleanup(self, max_age: float = 600) -> int:
        """Remove stale scores older than max_age seconds."""
        cutoff = time.time() - max_age
        with self._lock:
            stale = [
                k for k, v in self._scores.items()
                # We don't store timestamp on AnomalyScore, so just prune by count
            ]
            # Simpler: keep only the most recent N entries
            if len(self._scores) > 10000:
                to_keep = dict(list(self._scores.items())[-5000:])
                removed = len(self._scores) - len(to_keep)
                self._scores = to_keep
                return removed

            # Prune old IP connection data
            for ip in list(self._ip_connections):
                times = self._ip_connections[ip]
                if times and times[-1] < cutoff:
                    del self._ip_connections[ip]

        return 0

    def get_stats(self) -> Dict:
        """Get detector statistics."""
        with self._lock:
            scored = len(self._scores)
            anomalous = sum(1 for s in self._scores.values() if s.is_anomalous)
            tracked_ips = len(self._ip_connections)

        return {
            "scored_flows": scored,
            "anomalous_flows": anomalous,
            "tracked_ips": tracked_ips,
        }
