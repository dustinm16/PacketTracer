"""Database-backed flow tracker with compatible interface."""

import threading
from typing import Dict, Optional, List, TYPE_CHECKING

from capture.parser import ParsedPacket
from config import FLOW_TIMEOUT, MAX_FLOWS
from .flow import Flow, FlowKey

if TYPE_CHECKING:
    from db.repositories.flow_repo import FlowRepository, FlowRecord


class DBFlowTracker:
    """Database-backed flow tracker with interface compatible with FlowTracker.

    This class provides the same interface as FlowTracker but stores all data
    in SQLite via the FlowRepository. It maintains a small in-memory buffer
    for the current batch of updates.
    """

    def __init__(
        self,
        flow_repo: "FlowRepository",
        session_id: int,
        max_flows: int = MAX_FLOWS,
        timeout: float = FLOW_TIMEOUT
    ):
        self.flow_repo = flow_repo
        self.session_id = session_id
        self.max_flows = max_flows
        self.timeout = timeout
        self._lock = threading.Lock()

        # In-memory accumulator for current batch
        # Maps flow_key -> accumulated packet data for this batch
        self._pending: Dict[str, dict] = {}

        # Statistics (updated in real-time for immediate access)
        self._total_packets = 0
        self._total_bytes = 0

    def _normalize_key(self, key: FlowKey) -> FlowKey:
        """Normalize flow key to ensure bidirectional flows use same key."""
        reverse_key = (key[1], key[0], key[3], key[2], key[4])
        return min(key, reverse_key)

    def _flow_key_str(self, key: FlowKey) -> str:
        """Convert flow key tuple to string."""
        return f"{key[0]}:{key[2]}-{key[1]}:{key[3]}-{key[4]}"

    def process_packet(self, packet: ParsedPacket) -> Flow:
        """Process a packet and queue database update."""
        key = self._normalize_key(packet.flow_key)
        is_outbound = key == packet.flow_key
        key_str = self._flow_key_str(key)

        with self._lock:
            self._total_packets += 1
            self._total_bytes += packet.length

            # Accumulate in pending buffer
            if key_str not in self._pending:
                # New flow
                if is_outbound:
                    self._pending[key_str] = {
                        "src_ip": packet.src_ip,
                        "dst_ip": packet.dst_ip,
                        "src_port": packet.src_port,
                        "dst_port": packet.dst_port,
                        "protocol": packet.protocol,
                        "protocol_name": packet.protocol_name,
                        "packets_sent": 0,
                        "packets_recv": 0,
                        "bytes_sent": 0,
                        "bytes_recv": 0,
                        "first_seen": packet.timestamp,
                        "last_seen": packet.timestamp,
                        "min_ttl": packet.ttl,
                        "max_ttl": packet.ttl,
                    }
                else:
                    self._pending[key_str] = {
                        "src_ip": packet.dst_ip,
                        "dst_ip": packet.src_ip,
                        "src_port": packet.dst_port,
                        "dst_port": packet.src_port,
                        "protocol": packet.protocol,
                        "protocol_name": packet.protocol_name,
                        "packets_sent": 0,
                        "packets_recv": 0,
                        "bytes_sent": 0,
                        "bytes_recv": 0,
                        "first_seen": packet.timestamp,
                        "last_seen": packet.timestamp,
                        "min_ttl": packet.ttl,
                        "max_ttl": packet.ttl,
                    }

            # Update accumulated data
            pending = self._pending[key_str]
            pending["last_seen"] = packet.timestamp
            pending["min_ttl"] = min(pending["min_ttl"], packet.ttl)
            pending["max_ttl"] = max(pending["max_ttl"], packet.ttl)

            if is_outbound:
                pending["packets_sent"] += 1
                pending["bytes_sent"] += packet.length
            else:
                pending["packets_recv"] += 1
                pending["bytes_recv"] += packet.length

        # Queue update to database (async via writer)
        self.flow_repo.process_packet_update(key_str, pending.copy())

        # Return a Flow object for immediate use
        return self._pending_to_flow(key_str, pending)

    def _pending_to_flow(self, key_str: str, data: dict) -> Flow:
        """Convert pending data to Flow object."""
        return Flow(
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            src_port=data["src_port"],
            dst_port=data["dst_port"],
            protocol=data["protocol"],
            protocol_name=data["protocol_name"],
            packets_sent=data["packets_sent"],
            packets_recv=data["packets_recv"],
            bytes_sent=data["bytes_sent"],
            bytes_recv=data["bytes_recv"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            min_ttl=data["min_ttl"],
            max_ttl=data["max_ttl"],
            ttl_values=[],  # Not tracked in pending
        )

    def _record_to_flow(self, record: "FlowRecord") -> Flow:
        """Convert FlowRecord to Flow object for compatibility."""
        flow = Flow(
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            src_port=record.src_port,
            dst_port=record.dst_port,
            protocol=record.protocol,
            protocol_name=record.protocol_name,
            packets_sent=record.packets_sent,
            packets_recv=record.packets_recv,
            bytes_sent=record.bytes_sent,
            bytes_recv=record.bytes_recv,
            first_seen=record.first_seen,
            last_seen=record.last_seen,
            min_ttl=record.min_ttl,
            max_ttl=record.max_ttl,
            ttl_values=[],
        )
        # Attach geo data if available
        if record.dst_country:
            flow.dst_geo = {
                "country": record.dst_country,
                "country_code": record.dst_country_code,
                "city": record.dst_city,
                "isp": record.dst_isp,
                "as_name": record.dst_as_name,
            }
        if record.src_country:
            flow.src_geo = {
                "country": record.src_country,
                "city": record.src_city,
                "isp": record.src_isp,
            }
        return flow

    def get_flows(self) -> List[Flow]:
        """Get list of all flows from database."""
        records = self.flow_repo.get_flows(limit=self.max_flows)
        return [self._record_to_flow(r) for r in records]

    def get_flow(self, key: FlowKey) -> Optional[Flow]:
        """Get a specific flow by key."""
        normalized_key = self._normalize_key(key)
        key_str = self._flow_key_str(normalized_key)
        record = self.flow_repo.get_flow(key_str)
        if record:
            return self._record_to_flow(record)
        return None

    def get_active_flows(self, timeout: float = 60) -> List[Flow]:
        """Get flows active within the timeout period."""
        records = self.flow_repo.get_flows(
            limit=self.max_flows,
            active_within=timeout
        )
        return [self._record_to_flow(r) for r in records]

    def get_top_flows(self, n: int = 10, by: str = "bytes") -> List[Flow]:
        """Get top N flows by bytes or packets."""
        sort_by = "bytes" if by == "bytes" else "packets"
        records = self.flow_repo.get_flows(limit=n, sort_by=sort_by)
        return [self._record_to_flow(r) for r in records]

    def get_flows_filtered(
        self,
        protocol: Optional[str] = None,
        ip_filter: Optional[str] = None,
        port_filter: Optional[int] = None,
        limit: int = 100,
        sort_by: str = "bytes",
        flow_keys: Optional[set] = None,
    ) -> List[Flow]:
        """Get flows with filtering (new method for panels)."""
        records = self.flow_repo.get_flows(
            limit=limit,
            sort_by=sort_by,
            protocol=protocol,
            ip_filter=ip_filter,
            port_filter=port_filter,
            flow_keys=flow_keys,
        )
        return [self._record_to_flow(r) for r in records]

    def cleanup_expired(self) -> int:
        """No-op for database tracker (handled by pruning queries)."""
        return 0

    @property
    def flow_count(self) -> int:
        """Get current number of tracked flows."""
        return self.flow_repo.get_flow_count()

    @property
    def total_packets(self) -> int:
        """Get total packets processed."""
        return self._total_packets

    @property
    def total_bytes(self) -> int:
        """Get total bytes processed."""
        return self._total_bytes

    def get_stats(self) -> dict:
        """Get aggregate statistics from database."""
        return self.flow_repo.get_total_stats()

    def get_protocol_stats(self) -> List[dict]:
        """Get traffic grouped by protocol."""
        return self.flow_repo.get_protocol_stats()

    def get_country_stats(self) -> List[dict]:
        """Get traffic grouped by country."""
        return self.flow_repo.get_country_stats()

    def get_isp_stats(self) -> List[dict]:
        """Get traffic grouped by ISP."""
        return self.flow_repo.get_isp_stats()

    def get_category_stats(self) -> List[dict]:
        """Get traffic grouped by category."""
        return self.flow_repo.get_category_stats()

    def get_top_destinations(self, limit: int = 10) -> List[dict]:
        """Get top destinations by traffic."""
        return self.flow_repo.get_top_destinations(limit=limit)
