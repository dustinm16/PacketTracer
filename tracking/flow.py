"""Flow tracking - aggregate packets into flows."""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List
from collections import OrderedDict

from capture.parser import ParsedPacket
from config import FLOW_TIMEOUT, MAX_FLOWS


@dataclass
class Flow:
    """Represents a network flow (bidirectional connection)."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    protocol_name: str

    # Statistics
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0

    # Timing
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # TTL tracking (for hop estimation)
    ttl_values: List[int] = field(default_factory=list)
    min_ttl: int = 255
    max_ttl: int = 0

    # Geo/ISP data (populated later)
    src_geo: Optional[Dict] = None
    dst_geo: Optional[Dict] = None

    @property
    def flow_key(self) -> str:
        """Unique identifier for this flow (5-tuple)."""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_recv

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def estimated_hops(self) -> Optional[int]:
        """Estimate hops based on TTL values."""
        if not self.ttl_values:
            return None
        # Common initial TTL values: 64 (Linux/Mac), 128 (Windows), 255 (network devices)
        min_ttl = min(self.ttl_values)
        if min_ttl > 128:
            return 255 - min_ttl
        elif min_ttl > 64:
            return 128 - min_ttl
        else:
            return 64 - min_ttl

    def update_from_packet(self, packet: ParsedPacket, is_outbound: bool) -> None:
        """Update flow statistics from a packet."""
        self.last_seen = packet.timestamp

        if is_outbound:
            self.packets_sent += 1
            self.bytes_sent += packet.length
        else:
            self.packets_recv += 1
            self.bytes_recv += packet.length

        # Track TTL
        self.ttl_values.append(packet.ttl)
        self.min_ttl = min(self.min_ttl, packet.ttl)
        self.max_ttl = max(self.max_ttl, packet.ttl)

        # Keep only last 100 TTL values to save memory
        if len(self.ttl_values) > 100:
            self.ttl_values = self.ttl_values[-100:]

    def is_expired(self, timeout: float = FLOW_TIMEOUT, now: Optional[float] = None) -> bool:
        """Check if flow has expired."""
        if now is None:
            now = time.time()
        return (now - self.last_seen) > timeout


FlowKey = Tuple[str, str, int, int, int]


class FlowTracker:
    """Tracks and aggregates packet flows."""

    def __init__(self, max_flows: int = MAX_FLOWS, timeout: float = FLOW_TIMEOUT):
        self._flows: OrderedDict[FlowKey, Flow] = OrderedDict()
        self._lock = threading.Lock()
        self.max_flows = max_flows
        self.timeout = timeout

        # Statistics
        self.total_packets = 0
        self.total_bytes = 0

    def _normalize_key(self, key: FlowKey) -> FlowKey:
        """Normalize flow key to ensure bidirectional flows use same key."""
        reverse_key = (key[1], key[0], key[3], key[2], key[4])
        # Always use the lexicographically smaller key
        return min(key, reverse_key)

    def process_packet(self, packet: ParsedPacket) -> Flow:
        """Process a packet and update/create its flow."""
        key = self._normalize_key(packet.flow_key)
        is_outbound = key == packet.flow_key

        with self._lock:
            self.total_packets += 1
            self.total_bytes += packet.length

            if key in self._flows:
                flow = self._flows[key]
                flow.update_from_packet(packet, is_outbound)
                # Move to end for LRU-like behavior
                self._flows.move_to_end(key)
            else:
                # Create new flow
                if is_outbound:
                    flow = Flow(
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        src_port=packet.src_port,
                        dst_port=packet.dst_port,
                        protocol=packet.protocol,
                        protocol_name=packet.protocol_name,
                        first_seen=packet.timestamp,
                        last_seen=packet.timestamp,
                    )
                else:
                    flow = Flow(
                        src_ip=packet.dst_ip,
                        dst_ip=packet.src_ip,
                        src_port=packet.dst_port,
                        dst_port=packet.src_port,
                        protocol=packet.protocol,
                        protocol_name=packet.protocol_name,
                        first_seen=packet.timestamp,
                        last_seen=packet.timestamp,
                    )
                flow.update_from_packet(packet, is_outbound)
                self._flows[key] = flow

                # Prune if needed
                if len(self._flows) > self.max_flows:
                    self._prune_flows()

            return flow

    def _prune_flows(self) -> None:
        """Remove expired flows or oldest flows if over capacity."""
        now = time.time()
        expired_keys = [
            k for k, v in self._flows.items() if v.is_expired(self.timeout, now)
        ]
        for k in expired_keys:
            del self._flows[k]

        # If still over capacity, remove oldest
        while len(self._flows) > self.max_flows:
            self._flows.popitem(last=False)

    def get_flows(self) -> List[Flow]:
        """Get list of all active flows."""
        with self._lock:
            return list(self._flows.values())

    def get_flow(self, key: FlowKey) -> Optional[Flow]:
        """Get a specific flow by key."""
        normalized_key = self._normalize_key(key)
        with self._lock:
            return self._flows.get(normalized_key)

    def get_active_flows(self, timeout: float = 60) -> List[Flow]:
        """Get flows active within the timeout period."""
        now = time.time()
        with self._lock:
            return [f for f in self._flows.values() if (now - f.last_seen) < timeout]

    def get_top_flows(self, n: int = 10, by: str = "bytes") -> List[Flow]:
        """Get top N flows by bytes or packets."""
        with self._lock:
            flows = list(self._flows.values())

        if by == "bytes":
            flows.sort(key=lambda f: f.total_bytes, reverse=True)
        else:
            flows.sort(key=lambda f: f.total_packets, reverse=True)

        return flows[:n]

    def cleanup_expired(self) -> int:
        """Remove expired flows and return count removed."""
        with self._lock:
            initial_count = len(self._flows)
            self._prune_flows()
            return initial_count - len(self._flows)

    @property
    def flow_count(self) -> int:
        """Get current number of tracked flows."""
        with self._lock:
            return len(self._flows)
