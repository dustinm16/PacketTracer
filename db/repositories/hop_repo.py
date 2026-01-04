"""Hop repository for traceroute and latency data."""

import time
import hashlib
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from ..connection import ConnectionPool
    from ..writer import DatabaseWriter

from ..writer import WriteOp


@dataclass
class TracerouteRecord:
    """Traceroute session record."""
    id: int
    session_id: int
    target_ip: str
    target_hostname: Optional[str]
    started_at: float
    completed_at: Optional[float]
    total_hops: int
    reached_target: bool

    @property
    def duration(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    @property
    def is_complete(self) -> bool:
        return self.completed_at is not None


@dataclass
class HopRecord:
    """Hop node with latency data."""
    id: int
    traceroute_id: int
    hop_number: int
    ip: Optional[str]
    hostname: Optional[str]
    domain: Optional[str]
    # Latency
    rtt_min: Optional[float]
    rtt_max: Optional[float]
    rtt_avg: Optional[float]
    rtt_samples: int
    # Packet loss
    probes_sent: int
    probes_received: int
    loss_percent: float
    # Geo
    country: Optional[str]
    country_code: Optional[str]
    city: Optional[str]
    isp: Optional[str]
    as_name: Optional[str]
    as_number: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    # Status
    is_timeout: bool
    is_target: bool
    measured_at: float

    @property
    def location_str(self) -> str:
        """Format location as string."""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.country:
            parts.append(self.country)
        return ", ".join(parts) if parts else ""

    @property
    def display_name(self) -> str:
        """Get best display name for this hop."""
        if self.hostname:
            return self.hostname
        if self.ip:
            return self.ip
        return "*"


@dataclass
class PathSummaryRecord:
    """Network path summary."""
    id: int
    session_id: int
    src_ip: str
    dst_ip: str
    hop_count: int
    avg_latency: Optional[float]
    total_latency: Optional[float]
    path_hash: Optional[str]
    first_seen: float
    last_seen: float
    sample_count: int


class HopRepository:
    """Repository for traceroute and hop data."""

    def __init__(self, pool: "ConnectionPool", writer: "DatabaseWriter"):
        self.pool = pool
        self.writer = writer
        self._session_id: Optional[int] = None

    def set_session(self, session_id: int) -> None:
        """Set current session for writes."""
        self._session_id = session_id

    # Traceroute operations

    def create_traceroute(
        self,
        target_ip: str,
        target_hostname: Optional[str] = None,
        session_id: Optional[int] = None
    ) -> int:
        """Create a new traceroute session."""
        sid = session_id or self._session_id
        if sid is None:
            raise ValueError("No session ID set")

        with self.pool.write_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO traceroutes (
                    session_id, target_ip, target_hostname, started_at,
                    total_hops, reached_target
                ) VALUES (?, ?, ?, ?, 0, 0)
            """, [sid, target_ip, target_hostname, time.time()])
            conn.commit()
            return cursor.lastrowid

    def complete_traceroute(
        self,
        traceroute_id: int,
        total_hops: int,
        reached_target: bool
    ) -> None:
        """Mark a traceroute as complete."""
        data = {
            "traceroute_id": traceroute_id,
            "completed_at": time.time(),
            "total_hops": total_hops,
            "reached_target": 1 if reached_target else 0,
        }
        self.writer.queue_write(WriteOp.UPDATE_TRACEROUTE, data)

    def get_traceroute(self, traceroute_id: int) -> Optional[TracerouteRecord]:
        """Get a traceroute by ID."""
        row = self.pool.execute_read_one(
            "SELECT * FROM traceroutes WHERE id = ?",
            (traceroute_id,)
        )
        if row:
            return self._row_to_traceroute(row)
        return None

    def get_traceroutes(
        self,
        session_id: Optional[int] = None,
        target_ip: Optional[str] = None,
        limit: int = 50
    ) -> list[TracerouteRecord]:
        """Get traceroutes with optional filtering."""
        sid = session_id or self._session_id
        if sid is None:
            return []

        where = ["session_id = ?"]
        params = [sid]

        if target_ip:
            where.append("target_ip = ?")
            params.append(target_ip)

        params.append(limit)

        rows = self.pool.execute_read(f"""
            SELECT * FROM traceroutes
            WHERE {' AND '.join(where)}
            ORDER BY started_at DESC
            LIMIT ?
        """, tuple(params))

        return [self._row_to_traceroute(row) for row in rows]

    # Hop operations

    def upsert_hop(
        self,
        traceroute_id: int,
        hop_number: int,
        ip: Optional[str] = None,
        hostname: Optional[str] = None,
        domain: Optional[str] = None,
        rtt: Optional[float] = None,
        is_timeout: bool = False,
        is_target: bool = False,
        geo_data: Optional[dict] = None,
    ) -> None:
        """Record or update a hop."""
        now = time.time()
        data = {
            "traceroute_id": traceroute_id,
            "hop_number": hop_number,
            "ip": ip,
            "hostname": hostname,
            "domain": domain,
            "rtt_min": rtt,
            "rtt_max": rtt,
            "rtt_avg": rtt,
            "rtt_samples": 1 if rtt else 0,
            "probes_sent": 1,
            "probes_received": 0 if is_timeout else 1,
            "loss_percent": 100.0 if is_timeout else 0.0,
            "is_timeout": 1 if is_timeout else 0,
            "is_target": 1 if is_target else 0,
            "measured_at": now,
            # Geo data
            "country": None,
            "country_code": None,
            "city": None,
            "isp": None,
            "as_name": None,
            "as_number": None,
            "latitude": None,
            "longitude": None,
        }

        if geo_data:
            data.update({
                "country": geo_data.get("country"),
                "country_code": geo_data.get("country_code"),
                "city": geo_data.get("city"),
                "isp": geo_data.get("isp"),
                "as_name": geo_data.get("as_name"),
                "as_number": geo_data.get("as_number"),
                "latitude": geo_data.get("latitude"),
                "longitude": geo_data.get("longitude"),
            })

        self.writer.queue_write(WriteOp.UPSERT_HOP, data)

    def add_latency_sample(
        self,
        hop_id: int,
        rtt: float,
        probe_number: int
    ) -> None:
        """Add a latency sample for detailed tracking."""
        data = {
            "hop_id": hop_id,
            "rtt": rtt,
            "probe_number": probe_number,
            "measured_at": time.time(),
        }
        self.writer.queue_write(WriteOp.INSERT_LATENCY_SAMPLE, data)

    def get_hops(self, traceroute_id: int) -> list[HopRecord]:
        """Get all hops for a traceroute."""
        rows = self.pool.execute_read("""
            SELECT * FROM hops
            WHERE traceroute_id = ?
            ORDER BY hop_number ASC
        """, (traceroute_id,))

        return [self._row_to_hop(row) for row in rows]

    def get_hop(
        self,
        traceroute_id: int,
        hop_number: int
    ) -> Optional[HopRecord]:
        """Get a specific hop."""
        row = self.pool.execute_read_one("""
            SELECT * FROM hops
            WHERE traceroute_id = ? AND hop_number = ?
        """, (traceroute_id, hop_number))

        if row:
            return self._row_to_hop(row)
        return None

    def get_latency_samples(self, hop_id: int) -> list[dict]:
        """Get all latency samples for a hop."""
        rows = self.pool.execute_read("""
            SELECT rtt, probe_number, measured_at
            FROM latency_samples
            WHERE hop_id = ?
            ORDER BY probe_number ASC
        """, (hop_id,))

        return [dict(row) for row in rows]

    # Path summary operations

    def update_path_summary(
        self,
        src_ip: str,
        dst_ip: str,
        hops: list[HopRecord],
        session_id: Optional[int] = None
    ) -> None:
        """Update path summary from traceroute results."""
        sid = session_id or self._session_id
        if sid is None:
            return

        # Calculate stats
        hop_count = len(hops)
        valid_hops = [h for h in hops if h.rtt_avg is not None]
        avg_latency = sum(h.rtt_avg for h in valid_hops) / len(valid_hops) if valid_hops else None
        total_latency = sum(h.rtt_avg for h in valid_hops) if valid_hops else None

        # Create path hash from hop IPs
        hop_ips = [h.ip or "*" for h in hops]
        path_hash = hashlib.md5("|".join(hop_ips).encode()).hexdigest()[:16]

        now = time.time()
        data = {
            "session_id": sid,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "hop_count": hop_count,
            "avg_latency": avg_latency,
            "total_latency": total_latency,
            "path_hash": path_hash,
            "first_seen": now,
            "last_seen": now,
            "sample_count": 1,
        }
        self.writer.queue_write(WriteOp.UPSERT_PATH_SUMMARY, data)

    def get_path_summary(
        self,
        src_ip: str,
        dst_ip: str,
        session_id: Optional[int] = None
    ) -> Optional[PathSummaryRecord]:
        """Get path summary for a source-destination pair."""
        sid = session_id or self._session_id
        if sid is None:
            return None

        row = self.pool.execute_read_one("""
            SELECT * FROM path_summary
            WHERE session_id = ? AND src_ip = ? AND dst_ip = ?
        """, (sid, src_ip, dst_ip))

        if row:
            return self._row_to_path_summary(row)
        return None

    def get_path_summaries(
        self,
        session_id: Optional[int] = None,
        limit: int = 50
    ) -> list[PathSummaryRecord]:
        """Get all path summaries for a session."""
        sid = session_id or self._session_id
        if sid is None:
            return []

        rows = self.pool.execute_read("""
            SELECT * FROM path_summary
            WHERE session_id = ?
            ORDER BY last_seen DESC
            LIMIT ?
        """, (sid, limit))

        return [self._row_to_path_summary(row) for row in rows]

    # Stats

    def get_hop_stats(self, session_id: Optional[int] = None) -> dict:
        """Get aggregate hop statistics."""
        sid = session_id or self._session_id
        if sid is None:
            return {}

        row = self.pool.execute_read_one("""
            SELECT
                COUNT(DISTINCT t.id) as traceroute_count,
                AVG(t.total_hops) as avg_hops,
                SUM(CASE WHEN t.reached_target = 1 THEN 1 ELSE 0 END) as successful_traces,
                (SELECT AVG(h.rtt_avg) FROM hops h
                 JOIN traceroutes t2 ON h.traceroute_id = t2.id
                 WHERE t2.session_id = ?) as avg_latency
            FROM traceroutes t
            WHERE t.session_id = ?
        """, (sid, sid))

        if row:
            return {
                "traceroute_count": row["traceroute_count"] or 0,
                "avg_hops": row["avg_hops"],
                "successful_traces": row["successful_traces"] or 0,
                "avg_latency": row["avg_latency"],
            }
        return {}

    # Conversion helpers

    def _row_to_traceroute(self, row) -> TracerouteRecord:
        return TracerouteRecord(
            id=row["id"],
            session_id=row["session_id"],
            target_ip=row["target_ip"],
            target_hostname=row["target_hostname"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            total_hops=row["total_hops"],
            reached_target=bool(row["reached_target"]),
        )

    def _row_to_hop(self, row) -> HopRecord:
        return HopRecord(
            id=row["id"],
            traceroute_id=row["traceroute_id"],
            hop_number=row["hop_number"],
            ip=row["ip"],
            hostname=row["hostname"],
            domain=row["domain"],
            rtt_min=row["rtt_min"],
            rtt_max=row["rtt_max"],
            rtt_avg=row["rtt_avg"],
            rtt_samples=row["rtt_samples"],
            probes_sent=row["probes_sent"],
            probes_received=row["probes_received"],
            loss_percent=row["loss_percent"],
            country=row["country"],
            country_code=row["country_code"],
            city=row["city"],
            isp=row["isp"],
            as_name=row["as_name"],
            as_number=row["as_number"],
            latitude=row["latitude"],
            longitude=row["longitude"],
            is_timeout=bool(row["is_timeout"]),
            is_target=bool(row["is_target"]),
            measured_at=row["measured_at"],
        )

    def _row_to_path_summary(self, row) -> PathSummaryRecord:
        return PathSummaryRecord(
            id=row["id"],
            session_id=row["session_id"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            hop_count=row["hop_count"],
            avg_latency=row["avg_latency"],
            total_latency=row["total_latency"],
            path_hash=row["path_hash"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            sample_count=row["sample_count"],
        )
