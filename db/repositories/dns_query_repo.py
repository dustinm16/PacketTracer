"""DNS query repository for captured DNS traffic."""

import json
import time
from typing import Optional, List, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from ..connection import ConnectionPool
    from ..writer import DatabaseWriter

from ..writer import WriteOp


@dataclass
class DNSQueryRecord:
    """Recorded DNS query/response."""
    id: int
    session_id: int
    timestamp: float
    transaction_id: int
    src_ip: str
    dst_ip: str
    query_name: str
    query_type: int
    query_type_name: str
    is_response: bool
    response_code: Optional[int] = None
    response_code_name: Optional[str] = None
    answer_count: int = 0
    answers: List[dict] = field(default_factory=list)
    latency_ms: Optional[float] = None
    is_nxdomain: bool = False
    is_error: bool = False


@dataclass
class DNSStatsRecord:
    """Aggregated DNS statistics per domain."""
    id: int
    session_id: int
    query_name: str
    query_count: int
    response_count: int
    nxdomain_count: int
    error_count: int
    avg_latency_ms: Optional[float]
    first_seen: float
    last_seen: float
    unique_query_types: List[str] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)


class DNSQueryRepository:
    """Repository for DNS query data."""

    def __init__(self, pool: "ConnectionPool", writer: "DatabaseWriter"):
        self.pool = pool
        self.writer = writer
        self._session_id: Optional[int] = None

    def set_session(self, session_id: int) -> None:
        """Set the current session ID."""
        self._session_id = session_id

    def record_query(
        self,
        timestamp: float,
        transaction_id: int,
        src_ip: str,
        dst_ip: str,
        query_name: str,
        query_type: int,
        query_type_name: str,
        is_response: bool,
        response_code: Optional[int] = None,
        response_code_name: Optional[str] = None,
        answers: Optional[List[dict]] = None,
    ) -> None:
        """Record a DNS query or response."""
        if self._session_id is None:
            return

        is_nxdomain = response_code == 3 if response_code is not None else False
        is_error = response_code not in (None, 0) if response_code is not None else False

        data = {
            "session_id": self._session_id,
            "timestamp": timestamp,
            "transaction_id": transaction_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "query_name": query_name,
            "query_type": query_type,
            "query_type_name": query_type_name,
            "is_response": 1 if is_response else 0,
            "response_code": response_code,
            "response_code_name": response_code_name,
            "answer_count": len(answers) if answers else 0,
            "answers": json.dumps(answers) if answers else None,
            "is_nxdomain": 1 if is_nxdomain else 0,
            "is_error": 1 if is_error else 0,
        }
        self.writer.queue_write(WriteOp.INSERT_DNS_QUERY, data)

        # Also update stats
        self._update_stats(
            query_name=query_name,
            query_type_name=query_type_name,
            is_response=is_response,
            is_nxdomain=is_nxdomain,
            is_error=is_error,
            timestamp=timestamp,
            answers=answers,
        )

    def _update_stats(
        self,
        query_name: str,
        query_type_name: str,
        is_response: bool,
        is_nxdomain: bool,
        is_error: bool,
        timestamp: float,
        answers: Optional[List[dict]] = None,
    ) -> None:
        """Update DNS statistics for a domain."""
        if self._session_id is None:
            return

        # Extract IPs from answers
        resolved_ips = []
        if answers:
            for a in answers:
                if a.get("rtype") in (1, 28):  # A or AAAA
                    resolved_ips.append(a.get("rdata", ""))

        data = {
            "session_id": self._session_id,
            "query_name": query_name,
            "query_type_name": query_type_name,
            "is_response": is_response,
            "is_nxdomain": is_nxdomain,
            "is_error": is_error,
            "timestamp": timestamp,
            "resolved_ips": ",".join(resolved_ips) if resolved_ips else None,
        }
        self.writer.queue_write(WriteOp.UPSERT_DNS_STATS, data)

    def get_queries(
        self,
        session_id: Optional[int] = None,
        limit: int = 100,
        query_name: Optional[str] = None,
        query_type: Optional[str] = None,
        only_responses: bool = False,
        only_nxdomain: bool = False,
    ) -> List[DNSQueryRecord]:
        """Get DNS queries with optional filters."""
        session = session_id or self._session_id
        if session is None:
            return []

        sql = "SELECT * FROM dns_queries WHERE session_id = ?"
        params: List = [session]

        if query_name:
            sql += " AND query_name LIKE ?"
            params.append(f"%{query_name}%")

        if query_type:
            sql += " AND query_type_name = ?"
            params.append(query_type)

        if only_responses:
            sql += " AND is_response = 1"

        if only_nxdomain:
            sql += " AND is_nxdomain = 1"

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.pool.execute_read(sql, tuple(params))
        return [self._row_to_query_record(row) for row in rows]

    def get_stats(
        self,
        session_id: Optional[int] = None,
        limit: int = 50,
        order_by: str = "query_count",
    ) -> List[DNSStatsRecord]:
        """Get DNS statistics, ordered by count or other field."""
        session = session_id or self._session_id
        if session is None:
            return []

        order_column = {
            "query_count": "query_count DESC",
            "nxdomain": "nxdomain_count DESC",
            "error": "error_count DESC",
            "recent": "last_seen DESC",
        }.get(order_by, "query_count DESC")

        rows = self.pool.execute_read(f"""
            SELECT * FROM dns_stats
            WHERE session_id = ?
            ORDER BY {order_column}
            LIMIT ?
        """, (session, limit))

        return [self._row_to_stats_record(row) for row in rows]

    def get_top_queried_domains(
        self,
        session_id: Optional[int] = None,
        limit: int = 20,
    ) -> List[dict]:
        """Get top queried domains with counts."""
        session = session_id or self._session_id
        if session is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                query_name,
                query_count,
                response_count,
                nxdomain_count,
                error_count,
                avg_latency_ms
            FROM dns_stats
            WHERE session_id = ?
            ORDER BY query_count DESC
            LIMIT ?
        """, (session, limit))

        return [dict(row) for row in rows]

    def get_nxdomain_domains(
        self,
        session_id: Optional[int] = None,
        limit: int = 50,
    ) -> List[dict]:
        """Get domains with NXDOMAIN responses (potential DGA or typos)."""
        session = session_id or self._session_id
        if session is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                query_name,
                nxdomain_count,
                first_seen,
                last_seen
            FROM dns_stats
            WHERE session_id = ? AND nxdomain_count > 0
            ORDER BY nxdomain_count DESC
            LIMIT ?
        """, (session, limit))

        return [dict(row) for row in rows]

    def get_query_type_breakdown(
        self,
        session_id: Optional[int] = None,
    ) -> List[dict]:
        """Get breakdown of DNS query types."""
        session = session_id or self._session_id
        if session is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                query_type_name,
                COUNT(*) as count
            FROM dns_queries
            WHERE session_id = ? AND is_response = 0
            GROUP BY query_type_name
            ORDER BY count DESC
        """, (session,))

        return [dict(row) for row in rows]

    def get_dns_servers(
        self,
        session_id: Optional[int] = None,
    ) -> List[dict]:
        """Get DNS servers used (destination IPs of queries)."""
        session = session_id or self._session_id
        if session is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                dst_ip as server_ip,
                COUNT(*) as query_count
            FROM dns_queries
            WHERE session_id = ? AND is_response = 0
            GROUP BY dst_ip
            ORDER BY query_count DESC
        """, (session,))

        return [dict(row) for row in rows]

    def get_recent_queries(
        self,
        session_id: Optional[int] = None,
        limit: int = 50,
    ) -> List[DNSQueryRecord]:
        """Get most recent DNS queries."""
        return self.get_queries(session_id=session_id, limit=limit)

    def _row_to_query_record(self, row) -> DNSQueryRecord:
        """Convert database row to DNSQueryRecord."""
        answers = []
        if row["answers"]:
            try:
                answers = json.loads(row["answers"])
            except:
                pass

        return DNSQueryRecord(
            id=row["id"],
            session_id=row["session_id"],
            timestamp=row["timestamp"],
            transaction_id=row["transaction_id"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            query_name=row["query_name"],
            query_type=row["query_type"],
            query_type_name=row["query_type_name"],
            is_response=bool(row["is_response"]),
            response_code=row["response_code"],
            response_code_name=row["response_code_name"],
            answer_count=row["answer_count"],
            answers=answers,
            latency_ms=row["latency_ms"],
            is_nxdomain=bool(row["is_nxdomain"]),
            is_error=bool(row["is_error"]),
        )

    def _row_to_stats_record(self, row) -> DNSStatsRecord:
        """Convert database row to DNSStatsRecord."""
        query_types = []
        if row["unique_query_types"]:
            query_types = row["unique_query_types"].split(",")

        resolved_ips = []
        if row["resolved_ips"]:
            resolved_ips = row["resolved_ips"].split(",")

        return DNSStatsRecord(
            id=row["id"],
            session_id=row["session_id"],
            query_name=row["query_name"],
            query_count=row["query_count"],
            response_count=row["response_count"],
            nxdomain_count=row["nxdomain_count"],
            error_count=row["error_count"],
            avg_latency_ms=row["avg_latency_ms"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            unique_query_types=query_types,
            resolved_ips=resolved_ips,
        )
