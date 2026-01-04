"""Session repository for managing capture sessions."""

import time
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from ..connection import ConnectionPool
    from ..writer import DatabaseWriter


@dataclass
class SessionRecord:
    """Database session record."""
    id: int
    started_at: float
    ended_at: Optional[float]
    interface: Optional[str]
    bpf_filter: Optional[str]
    total_packets: int
    total_bytes: int
    is_active: bool

    @property
    def duration(self) -> float:
        """Session duration in seconds."""
        end = self.ended_at or time.time()
        return end - self.started_at

    @property
    def packets_per_second(self) -> float:
        """Average packets per second."""
        if self.duration > 0:
            return self.total_packets / self.duration
        return 0.0


class SessionRepository:
    """Repository for session management."""

    def __init__(self, pool: "ConnectionPool", writer: "DatabaseWriter"):
        self.pool = pool
        self.writer = writer
        self._current_session_id: Optional[int] = None

    @property
    def current_session_id(self) -> Optional[int]:
        """Get the current active session ID."""
        return self._current_session_id

    def create_session(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip"
    ) -> int:
        """Create a new capture session."""
        with self.pool.write_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO sessions (started_at, interface, bpf_filter, is_active)
                VALUES (?, ?, ?, 1)
            """, [time.time(), interface, bpf_filter])
            conn.commit()
            self._current_session_id = cursor.lastrowid
            return self._current_session_id

    def end_session(self, session_id: Optional[int] = None) -> None:
        """Mark a session as ended."""
        sid = session_id or self._current_session_id
        if sid is None:
            return

        with self.pool.write_connection() as conn:
            conn.execute("""
                UPDATE sessions
                SET ended_at = ?, is_active = 0
                WHERE id = ?
            """, [time.time(), sid])
            conn.commit()

        if sid == self._current_session_id:
            self._current_session_id = None

    def increment_stats(
        self,
        session_id: int,
        packets: int = 0,
        bytes_count: int = 0
    ) -> None:
        """Increment session packet and byte counts.

        Uses atomic increment to avoid race conditions.
        """
        from ..writer import WriteOp
        self.writer.queue_write(WriteOp.UPDATE_SESSION_STATS, {
            "session_id": session_id,
            "packets": packets,
            "bytes": bytes_count,
        })

    def get_session(self, session_id: int) -> Optional[SessionRecord]:
        """Get a session by ID."""
        row = self.pool.execute_read_one(
            "SELECT * FROM sessions WHERE id = ?",
            (session_id,)
        )
        if row:
            return self._row_to_record(row)
        return None

    def get_current_session(self) -> Optional[SessionRecord]:
        """Get the current active session."""
        if self._current_session_id:
            return self.get_session(self._current_session_id)
        return None

    def get_active_sessions(self) -> list[SessionRecord]:
        """Get all active sessions."""
        rows = self.pool.execute_read(
            "SELECT * FROM sessions WHERE is_active = 1 ORDER BY started_at DESC"
        )
        return [self._row_to_record(row) for row in rows]

    def get_session_history(self, limit: int = 20) -> list[SessionRecord]:
        """Get list of past sessions."""
        rows = self.pool.execute_read("""
            SELECT * FROM sessions
            ORDER BY started_at DESC
            LIMIT ?
        """, (limit,))
        return [self._row_to_record(row) for row in rows]

    def get_session_stats(self, session_id: Optional[int] = None) -> dict:
        """Get aggregate statistics for a session."""
        sid = session_id or self._current_session_id
        if sid is None:
            return {"total_packets": 0, "total_bytes": 0, "flow_count": 0}

        row = self.pool.execute_read_one("""
            SELECT
                s.total_packets,
                s.total_bytes,
                (SELECT COUNT(*) FROM flows WHERE session_id = s.id) as flow_count
            FROM sessions s
            WHERE s.id = ?
        """, (sid,))

        if row:
            return {
                "total_packets": row["total_packets"],
                "total_bytes": row["total_bytes"],
                "flow_count": row["flow_count"],
            }
        return {"total_packets": 0, "total_bytes": 0, "flow_count": 0}

    def delete_session(self, session_id: int) -> bool:
        """Delete a session and all its data (cascades)."""
        with self.pool.write_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE id = ?",
                [session_id]
            )
            conn.commit()
            return cursor.rowcount > 0

    def cleanup_old_sessions(self, max_age_days: int = 30) -> int:
        """Delete sessions older than specified days."""
        cutoff = time.time() - (max_age_days * 86400)
        with self.pool.write_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM sessions
                WHERE ended_at IS NOT NULL AND ended_at < ? AND is_active = 0
            """, [cutoff])
            conn.commit()
            return cursor.rowcount

    def _row_to_record(self, row) -> SessionRecord:
        """Convert database row to SessionRecord."""
        return SessionRecord(
            id=row["id"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            interface=row["interface"],
            bpf_filter=row["bpf_filter"],
            total_packets=row["total_packets"],
            total_bytes=row["total_bytes"],
            is_active=bool(row["is_active"]),
        )
