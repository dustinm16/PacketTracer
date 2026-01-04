"""Port repository for port statistics."""

import time
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from ..connection import ConnectionPool
    from ..writer import DatabaseWriter

from ..writer import WriteOp


@dataclass
class PortRecord:
    """Database port statistics record."""
    id: int
    session_id: int
    port: int
    protocol: str
    packets_in: int
    packets_out: int
    bytes_in: int
    bytes_out: int
    hit_count: int
    unique_sources: int
    unique_destinations: int
    first_seen: float
    last_seen: float

    @property
    def total_packets(self) -> int:
        return self.packets_in + self.packets_out

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def packets_per_second(self) -> float:
        if self.duration > 0:
            return self.total_packets / self.duration
        return 0.0


class PortRepository:
    """Repository for port statistics."""

    def __init__(self, pool: "ConnectionPool", writer: "DatabaseWriter"):
        self.pool = pool
        self.writer = writer
        self._session_id: Optional[int] = None

    def set_session(self, session_id: int) -> None:
        """Set current session for writes."""
        self._session_id = session_id

    def record_port_activity(
        self,
        port: int,
        protocol: str,
        packets_in: int = 0,
        packets_out: int = 0,
        bytes_in: int = 0,
        bytes_out: int = 0,
        hit_count: int = 0,
        unique_sources: int = 0,
        unique_destinations: int = 0,
        first_seen: Optional[float] = None,
        last_seen: Optional[float] = None,
    ) -> None:
        """Record port activity (upsert)."""
        if self._session_id is None:
            return

        now = time.time()
        data = {
            "session_id": self._session_id,
            "port": port,
            "protocol": protocol,
            "packets_in": packets_in,
            "packets_out": packets_out,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "hit_count": hit_count,
            "unique_sources": unique_sources,
            "unique_destinations": unique_destinations,
            "first_seen": first_seen or now,
            "last_seen": last_seen or now,
        }
        self.writer.queue_write(WriteOp.UPSERT_PORT_STATS, data)

    def get_top_ports(
        self,
        session_id: Optional[int] = None,
        limit: int = 20,
        sort_by: str = "bytes"
    ) -> list[PortRecord]:
        """Get top ports by traffic."""
        session = session_id or self._session_id
        if session is None:
            return []

        sort_map = {
            "bytes": "(bytes_in + bytes_out)",
            "packets": "(packets_in + packets_out)",
            "hits": "hit_count",
            "connections": "unique_sources",
        }
        sort_col = sort_map.get(sort_by, sort_map["bytes"])

        rows = self.pool.execute_read(f"""
            SELECT * FROM port_stats
            WHERE session_id = ?
            ORDER BY {sort_col} DESC
            LIMIT ?
        """, (session, limit))

        return [self._row_to_record(row) for row in rows]

    def get_port_stats(
        self,
        port: int,
        protocol: str = "TCP",
        session_id: Optional[int] = None
    ) -> Optional[PortRecord]:
        """Get statistics for a specific port."""
        session = session_id or self._session_id
        if session is None:
            return None

        row = self.pool.execute_read_one(
            "SELECT * FROM port_stats WHERE session_id = ? AND port = ? AND protocol = ?",
            (session, port, protocol)
        )
        if row:
            return self._row_to_record(row)
        return None

    def get_port_range_stats(
        self,
        session_id: Optional[int] = None
    ) -> dict[str, dict]:
        """Get statistics by port range (well-known, registered, dynamic)."""
        session = session_id or self._session_id
        if session is None:
            return {}

        rows = self.pool.execute_read("""
            SELECT
                CASE
                    WHEN port < 1024 THEN 'well_known'
                    WHEN port < 49152 THEN 'registered'
                    ELSE 'dynamic'
                END as port_range,
                COUNT(*) as port_count,
                SUM(bytes_in + bytes_out) as total_bytes,
                SUM(packets_in + packets_out) as total_packets
            FROM port_stats
            WHERE session_id = ?
            GROUP BY port_range
        """, (session,))

        return {row["port_range"]: dict(row) for row in rows}

    def get_service_breakdown(
        self,
        session_id: Optional[int] = None
    ) -> list[dict]:
        """Get traffic grouped by common services."""
        session = session_id or self._session_id
        if session is None:
            return []

        # Map common ports to services
        rows = self.pool.execute_read("""
            SELECT
                CASE
                    WHEN port IN (80, 8080) THEN 'HTTP'
                    WHEN port IN (443, 8443) THEN 'HTTPS'
                    WHEN port = 22 THEN 'SSH'
                    WHEN port = 53 THEN 'DNS'
                    WHEN port IN (25, 465, 587) THEN 'SMTP'
                    WHEN port IN (110, 995) THEN 'POP3'
                    WHEN port IN (143, 993) THEN 'IMAP'
                    WHEN port = 21 THEN 'FTP'
                    WHEN port IN (3306, 5432, 1433, 27017) THEN 'Database'
                    WHEN port IN (6379, 11211) THEN 'Cache'
                    ELSE 'Other'
                END as service,
                SUM(bytes_in + bytes_out) as total_bytes,
                SUM(packets_in + packets_out) as total_packets,
                COUNT(*) as port_count
            FROM port_stats
            WHERE session_id = ?
            GROUP BY service
            ORDER BY total_bytes DESC
        """, (session,))

        return [dict(row) for row in rows]

    def _row_to_record(self, row) -> PortRecord:
        """Convert database row to PortRecord."""
        return PortRecord(
            id=row["id"],
            session_id=row["session_id"],
            port=row["port"],
            protocol=row["protocol"],
            packets_in=row["packets_in"],
            packets_out=row["packets_out"],
            bytes_in=row["bytes_in"],
            bytes_out=row["bytes_out"],
            hit_count=row["hit_count"],
            unique_sources=row["unique_sources"],
            unique_destinations=row["unique_destinations"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )
