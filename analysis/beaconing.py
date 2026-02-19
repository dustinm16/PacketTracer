"""Beaconing detection — identifies periodic connection patterns.

Beaconing is a hallmark of command-and-control (C2) traffic: malware
phones home at regular intervals. This detector tracks inter-connection
timing per (src_ip, dst_ip) pair and flags pairs with low jitter relative
to their mean interval.
"""

import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional


@dataclass
class BeaconCandidate:
    """A (src, dst) pair exhibiting periodic connection behavior."""
    src_ip: str
    dst_ip: str
    connection_count: int = 0
    mean_interval: float = 0.0  # average seconds between connections
    std_interval: float = 0.0   # standard deviation
    jitter_pct: float = 0.0     # std / mean * 100 — lower = more regular
    score: float = 0.0          # 0.0–1.0 beacon likelihood
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def is_beacon(self) -> bool:
        """Strong beacon signal."""
        return self.score >= 0.7

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen


class BeaconDetector:
    """Detect periodic (beaconing) connection patterns.

    For each (src_ip, dst_ip) pair, records connection timestamps and
    evaluates whether the inter-arrival time distribution looks periodic.

    A perfect beacon has zero jitter. Real-world C2 typically adds a
    small random sleep, resulting in 5-15% jitter. Normal user traffic
    has 50-100%+ jitter.
    """

    def __init__(
        self,
        min_connections: int = 6,
        max_jitter_pct: float = 25.0,
        max_pairs: int = 5000,
        window: float = 3600.0,
    ):
        """
        Args:
            min_connections: Minimum connections to evaluate a pair.
            max_jitter_pct: Maximum jitter percentage to consider beacon-like.
            max_pairs: Maximum tracked pairs before pruning oldest.
            window: Time window in seconds to consider (default 1 hour).
        """
        self.min_connections = min_connections
        self.max_jitter_pct = max_jitter_pct
        self.max_pairs = max_pairs
        self.window = window

        self._lock = threading.Lock()
        # (src_ip, dst_ip) -> list of timestamps
        self._pairs: Dict[tuple, Deque[float]] = defaultdict(lambda: deque(maxlen=200))

    def record_connection(self, src_ip: str, dst_ip: str, timestamp: Optional[float] = None) -> None:
        """Record a connection event for the pair."""
        if timestamp is None:
            timestamp = time.time()

        key = (src_ip, dst_ip)
        with self._lock:
            self._pairs[key].append(timestamp)

            if len(self._pairs) > self.max_pairs:
                self._prune()

    def evaluate_pair(self, src_ip: str, dst_ip: str) -> Optional[BeaconCandidate]:
        """Evaluate a specific pair for beacon behavior."""
        key = (src_ip, dst_ip)
        with self._lock:
            timestamps = list(self._pairs.get(key, []))

        if len(timestamps) < self.min_connections:
            return None

        return self._analyze_timestamps(src_ip, dst_ip, timestamps)

    def get_beacons(self, min_score: float = 0.5) -> List[BeaconCandidate]:
        """Evaluate all tracked pairs and return likely beacons."""
        results = []
        with self._lock:
            pairs_snapshot = {k: list(v) for k, v in self._pairs.items()}

        for (src_ip, dst_ip), timestamps in pairs_snapshot.items():
            if len(timestamps) < self.min_connections:
                continue
            candidate = self._analyze_timestamps(src_ip, dst_ip, timestamps)
            if candidate and candidate.score >= min_score:
                results.append(candidate)

        results.sort(key=lambda c: c.score, reverse=True)
        return results

    def _analyze_timestamps(
        self, src_ip: str, dst_ip: str, timestamps: List[float]
    ) -> Optional[BeaconCandidate]:
        """Compute beacon score from connection timestamps."""
        # Filter to window
        cutoff = time.time() - self.window
        timestamps = sorted(t for t in timestamps if t > cutoff)

        if len(timestamps) < self.min_connections:
            return None

        # Compute inter-arrival intervals
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if not intervals:
            return None

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 1.0:
            return None  # Sub-second intervals are too fast to be beaconing

        # Standard deviation
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_interval = math.sqrt(variance)

        # Jitter percentage
        jitter_pct = (std_interval / mean_interval * 100) if mean_interval > 0 else 100.0

        # Score: lower jitter = higher score
        # 0% jitter -> 1.0, 25%+ jitter -> ~0.0
        if jitter_pct <= 5:
            score = 1.0
        elif jitter_pct <= 10:
            score = 0.85
        elif jitter_pct <= 15:
            score = 0.7
        elif jitter_pct <= 25:
            score = 0.5
        elif jitter_pct <= 40:
            score = 0.3
        else:
            score = max(0.0, 0.2 - (jitter_pct - 40) / 200)

        # Boost score if many connections observed (higher confidence)
        if len(timestamps) >= 20:
            score = min(1.0, score * 1.15)

        # Reduce score for very short intervals (< 5 sec might be keepalive)
        if mean_interval < 5 and jitter_pct < 10:
            score *= 0.5  # Likely TCP keepalive, not C2

        return BeaconCandidate(
            src_ip=src_ip,
            dst_ip=dst_ip,
            connection_count=len(timestamps),
            mean_interval=mean_interval,
            std_interval=std_interval,
            jitter_pct=jitter_pct,
            score=score,
            first_seen=timestamps[0],
            last_seen=timestamps[-1],
        )

    def _prune(self) -> None:
        """Remove oldest pairs when over capacity."""
        # Sort by most recent timestamp, keep newest
        items = sorted(
            self._pairs.items(),
            key=lambda kv: kv[1][-1] if kv[1] else 0,
        )
        keep_count = int(self.max_pairs * 0.8)
        for key, _ in items[:-keep_count]:
            del self._pairs[key]

    def cleanup(self) -> int:
        """Remove pairs with no recent activity."""
        cutoff = time.time() - self.window
        removed = 0
        with self._lock:
            stale = [
                k for k, v in self._pairs.items()
                if not v or v[-1] < cutoff
            ]
            for k in stale:
                del self._pairs[k]
                removed += 1
        return removed

    def get_stats(self) -> Dict:
        """Get detector statistics."""
        with self._lock:
            total_pairs = len(self._pairs)
        beacons = self.get_beacons(min_score=0.5)
        return {
            "tracked_pairs": total_pairs,
            "beacon_candidates": len(beacons),
        }
