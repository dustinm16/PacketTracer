"""Flow repository for flow data access."""

import time
from typing import Optional, Any, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from ..connection import ConnectionPool
    from ..writer import DatabaseWriter

from ..writer import WriteOp


@dataclass
class FlowRecord:
    """Database flow record with all denormalized data."""
    id: int
    session_id: int
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    protocol_name: str
    packets_sent: int
    packets_recv: int
    bytes_sent: int
    bytes_recv: int
    first_seen: float
    last_seen: float
    min_ttl: int
    max_ttl: int
    # Geo fields
    src_country: Optional[str] = None
    src_country_code: Optional[str] = None
    src_city: Optional[str] = None
    src_isp: Optional[str] = None
    src_as_name: Optional[str] = None
    dst_country: Optional[str] = None
    dst_country_code: Optional[str] = None
    dst_city: Optional[str] = None
    dst_isp: Optional[str] = None
    dst_as_name: Optional[str] = None
    # DNS fields
    src_hostname: Optional[str] = None
    src_domain: Optional[str] = None
    src_fqdn: Optional[str] = None
    dst_hostname: Optional[str] = None
    dst_domain: Optional[str] = None
    dst_fqdn: Optional[str] = None
    # Classification
    category: Optional[str] = None
    subcategory: Optional[str] = None
    service: Optional[str] = None
    is_encrypted: bool = False
    classification_confidence: Optional[float] = None

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
    def estimated_hops(self) -> int:
        """Estimate hops based on TTL (common initial values: 64, 128, 255)."""
        if self.min_ttl <= 0:
            return 0
        for initial_ttl in [64, 128, 255]:
            if self.min_ttl <= initial_ttl:
                return initial_ttl - self.min_ttl
        return 0

    def to_dict(self) -> dict:
        """Convert to dictionary for compatibility with existing code."""
        return {
            "flow_key": self.flow_key,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "protocol_name": self.protocol_name,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "dst_geo": {
                "country": self.dst_country,
                "country_code": self.dst_country_code,
                "city": self.dst_city,
                "isp": self.dst_isp,
                "as_name": self.dst_as_name,
            } if self.dst_country else None,
            "src_geo": {
                "country": self.src_country,
                "city": self.src_city,
                "isp": self.src_isp,
            } if self.src_country else None,
            "dst_hostname": self.dst_hostname,
            "dst_domain": self.dst_domain,
            "category": self.category,
            "service": self.service,
            "is_encrypted": self.is_encrypted,
            "estimated_hops": self.estimated_hops,
        }


class FlowRepository:
    """Repository for flow data access."""

    def __init__(self, pool: "ConnectionPool", writer: "DatabaseWriter"):
        self.pool = pool
        self.writer = writer
        self._session_id: Optional[int] = None

        # In-memory cache of flow keys we know exist
        # (avoids INSERT vs UPDATE decision on every packet)
        self._known_flows: set[str] = set()

    def set_session(self, session_id: int) -> None:
        """Set current session for writes."""
        self._session_id = session_id
        self._known_flows.clear()

    def process_packet_update(
        self,
        flow_key: str,
        flow_data: dict,
    ) -> None:
        """Queue a flow upsert from packet processing.

        Uses UPSERT to handle both insert and update in one operation.
        """
        if self._session_id is None:
            return

        data = {
            **flow_data,
            "session_id": self._session_id,
            "flow_key": flow_key,
        }

        # Use upsert - handles both insert and update
        self.writer.queue_write(WriteOp.UPSERT_FLOW, data)
        self._known_flows.add(flow_key)

    def update_geo_data(
        self,
        flow_key: str,
        geo_data: dict,
        is_destination: bool = True
    ) -> None:
        """Update geo data for a flow."""
        if self._session_id is None:
            return

        prefix = "dst_" if is_destination else "src_"
        data = {
            "session_id": self._session_id,
            "flow_key": flow_key,
            f"{prefix}country": geo_data.get("country"),
            f"{prefix}country_code": geo_data.get("country_code"),
            f"{prefix}city": geo_data.get("city"),
            f"{prefix}isp": geo_data.get("isp"),
            f"{prefix}as_name": geo_data.get("as_name"),
            # Set other prefix to None so COALESCE works
            f"{'src_' if is_destination else 'dst_'}country": None,
            f"{'src_' if is_destination else 'dst_'}country_code": None,
            f"{'src_' if is_destination else 'dst_'}city": None,
            f"{'src_' if is_destination else 'dst_'}isp": None,
            f"{'src_' if is_destination else 'dst_'}as_name": None,
        }
        self.writer.queue_write(WriteOp.UPDATE_FLOW_GEO, data)

    def update_dns_data(
        self,
        flow_key: str,
        hostname: Optional[str],
        domain: Optional[str],
        fqdn: Optional[str] = None,
        is_destination: bool = True
    ) -> None:
        """Update DNS data for a flow."""
        if self._session_id is None:
            return

        prefix = "dst_" if is_destination else "src_"
        other_prefix = "src_" if is_destination else "dst_"
        data = {
            "session_id": self._session_id,
            "flow_key": flow_key,
            f"{prefix}hostname": hostname,
            f"{prefix}domain": domain,
            f"{prefix}fqdn": fqdn,
            # Set other prefix to None so COALESCE works
            f"{other_prefix}hostname": None,
            f"{other_prefix}domain": None,
            f"{other_prefix}fqdn": None,
        }
        self.writer.queue_write(WriteOp.UPDATE_FLOW_DNS, data)

    def update_classification(
        self,
        flow_key: str,
        category: str,
        confidence: float = 1.0,
        subcategory: Optional[str] = None,
        service: Optional[str] = None,
        is_encrypted: bool = False
    ) -> None:
        """Update classification for a flow."""
        if self._session_id is None:
            return

        data = {
            "session_id": self._session_id,
            "flow_key": flow_key,
            "category": category,
            "confidence": confidence,
            "subcategory": subcategory,
            "service": service,
            "is_encrypted": 1 if is_encrypted else 0,
        }
        self.writer.queue_write(WriteOp.UPDATE_FLOW_CLASSIFICATION, data)

    def get_flows(
        self,
        session_id: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "bytes",
        sort_desc: bool = True,
        protocol: Optional[str] = None,
        ip_filter: Optional[str] = None,
        port_filter: Optional[int] = None,
        active_within: Optional[float] = None,
        flow_keys: Optional[set[str]] = None,
    ) -> list[FlowRecord]:
        """Get flows with filtering and sorting."""
        session = session_id or self._session_id
        if session is None:
            return []

        # Build query with optional filters
        where_clauses = ["session_id = ?"]
        params: list[Any] = [session]

        if protocol:
            where_clauses.append("protocol_name = ?")
            params.append(protocol)

        if ip_filter:
            where_clauses.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
            params.extend([f"%{ip_filter}%", f"%{ip_filter}%"])

        if port_filter:
            where_clauses.append("(src_port = ? OR dst_port = ?)")
            params.extend([port_filter, port_filter])

        if active_within:
            cutoff = time.time() - active_within
            where_clauses.append("last_seen > ?")
            params.append(cutoff)

        if flow_keys:
            placeholders = ",".join("?" * len(flow_keys))
            where_clauses.append(f"flow_key IN ({placeholders})")
            params.extend(flow_keys)

        # Sort clause
        sort_map = {
            "bytes": "(bytes_sent + bytes_recv)",
            "packets": "(packets_sent + packets_recv)",
            "time": "last_seen",
            "first_seen": "first_seen",
            "duration": "(last_seen - first_seen)",
        }
        sort_col = sort_map.get(sort_by, sort_map["bytes"])
        order = "DESC" if sort_desc else "ASC"

        query = f"""
            SELECT * FROM flows
            WHERE {' AND '.join(where_clauses)}
            ORDER BY {sort_col} {order}
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        rows = self.pool.execute_read(query, tuple(params))
        return [self._row_to_record(row) for row in rows]

    def get_flow(
        self,
        flow_key: str,
        session_id: Optional[int] = None
    ) -> Optional[FlowRecord]:
        """Get a single flow by key."""
        session = session_id or self._session_id
        if session is None:
            return None

        row = self.pool.execute_read_one(
            "SELECT * FROM flows WHERE session_id = ? AND flow_key = ?",
            (session, flow_key)
        )
        if row:
            return self._row_to_record(row)
        return None

    def get_flow_count(self, session_id: Optional[int] = None) -> int:
        """Get total flow count for session."""
        session = session_id or self._session_id
        if session is None:
            return 0

        row = self.pool.execute_read_one(
            "SELECT COUNT(*) as count FROM flows WHERE session_id = ?",
            (session,)
        )
        return row["count"] if row else 0

    def get_total_stats(self, session_id: Optional[int] = None) -> dict[str, int]:
        """Get aggregate statistics for session."""
        session = session_id or self._session_id
        if session is None:
            return {"flow_count": 0, "total_bytes": 0, "total_packets": 0}

        row = self.pool.execute_read_one("""
            SELECT
                COUNT(*) as flow_count,
                COALESCE(SUM(bytes_sent + bytes_recv), 0) as total_bytes,
                COALESCE(SUM(packets_sent + packets_recv), 0) as total_packets
            FROM flows
            WHERE session_id = ?
        """, (session,))

        if row:
            return {
                "flow_count": row["flow_count"],
                "total_bytes": row["total_bytes"],
                "total_packets": row["total_packets"],
            }
        return {"flow_count": 0, "total_bytes": 0, "total_packets": 0}

    def get_protocol_stats(self, session_id: Optional[int] = None) -> list[dict]:
        """Get traffic grouped by protocol."""
        session = session_id or self._session_id
        if session is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                protocol_name,
                COUNT(*) as flow_count,
                SUM(bytes_sent + bytes_recv) as total_bytes,
                SUM(packets_sent + packets_recv) as total_packets
            FROM flows
            WHERE session_id = ?
            GROUP BY protocol_name
            ORDER BY total_bytes DESC
        """, (session,))

        return [dict(row) for row in rows]

    def get_country_stats(self, session_id: Optional[int] = None) -> list[dict]:
        """Get traffic grouped by destination country."""
        session = session_id or self._session_id
        if session is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                dst_country as country,
                dst_country_code as country_code,
                COUNT(*) as flow_count,
                SUM(bytes_sent + bytes_recv) as total_bytes
            FROM flows
            WHERE session_id = ? AND dst_country IS NOT NULL
            GROUP BY dst_country
            ORDER BY flow_count DESC
        """, (session,))

        return [dict(row) for row in rows]

    def get_isp_stats(self, session_id: Optional[int] = None) -> list[dict]:
        """Get traffic grouped by destination ISP."""
        session = session_id or self._session_id
        if session is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                dst_isp as isp,
                COUNT(*) as flow_count,
                SUM(bytes_sent + bytes_recv) as total_bytes
            FROM flows
            WHERE session_id = ? AND dst_isp IS NOT NULL
            GROUP BY dst_isp
            ORDER BY flow_count DESC
        """, (session,))

        return [dict(row) for row in rows]

    def get_top_destinations(
        self,
        session_id: Optional[int] = None,
        limit: int = 10
    ) -> list[dict]:
        """Get top destinations by traffic."""
        session = session_id or self._session_id
        if session is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                dst_ip,
                dst_hostname,
                dst_domain,
                dst_country,
                dst_isp,
                COUNT(*) as flow_count,
                SUM(bytes_sent + bytes_recv) as total_bytes,
                SUM(packets_sent + packets_recv) as total_packets
            FROM flows
            WHERE session_id = ?
            GROUP BY dst_ip
            ORDER BY total_bytes DESC
            LIMIT ?
        """, (session, limit))

        return [dict(row) for row in rows]

    def get_category_stats(self, session_id: Optional[int] = None) -> list[dict]:
        """Get traffic grouped by category."""
        session = session_id or self._session_id
        if session is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                category,
                COUNT(*) as flow_count,
                SUM(bytes_sent + bytes_recv) as total_bytes
            FROM flows
            WHERE session_id = ? AND category IS NOT NULL
            GROUP BY category
            ORDER BY total_bytes DESC
        """, (session,))

        return [dict(row) for row in rows]

    def _row_to_record(self, row) -> FlowRecord:
        """Convert database row to FlowRecord."""
        return FlowRecord(
            id=row["id"],
            session_id=row["session_id"],
            flow_key=row["flow_key"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            protocol_name=row["protocol_name"],
            packets_sent=row["packets_sent"],
            packets_recv=row["packets_recv"],
            bytes_sent=row["bytes_sent"],
            bytes_recv=row["bytes_recv"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            min_ttl=row["min_ttl"],
            max_ttl=row["max_ttl"],
            src_country=row["src_country"],
            src_country_code=row["src_country_code"],
            src_city=row["src_city"],
            src_isp=row["src_isp"],
            src_as_name=row["src_as_name"],
            dst_country=row["dst_country"],
            dst_country_code=row["dst_country_code"],
            dst_city=row["dst_city"],
            dst_isp=row["dst_isp"],
            dst_as_name=row["dst_as_name"],
            src_hostname=row["src_hostname"],
            src_domain=row["src_domain"],
            src_fqdn=row["src_fqdn"] if "src_fqdn" in row.keys() else None,
            dst_hostname=row["dst_hostname"],
            dst_domain=row["dst_domain"],
            dst_fqdn=row["dst_fqdn"] if "dst_fqdn" in row.keys() else None,
            category=row["category"],
            subcategory=row["subcategory"],
            service=row["service"],
            is_encrypted=bool(row["is_encrypted"]),
            classification_confidence=row["classification_confidence"],
        )
