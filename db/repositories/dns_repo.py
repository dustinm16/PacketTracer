"""DNS repository for DNS cache persistence."""

import time
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from ..connection import ConnectionPool
    from ..writer import DatabaseWriter

from ..writer import WriteOp


@dataclass
class DNSRecord:
    """Cached DNS information for an IP."""
    ip: str
    hostname: Optional[str]   # Short hostname (first part)
    domain: Optional[str]     # Base domain (e.g., "example.com")
    fqdn: Optional[str]       # Full Qualified Domain Name
    resolved: bool
    cached_at: float
    expires_at: float

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def short_hostname(self) -> Optional[str]:
        """Get shortened hostname (first part before domain)."""
        if self.fqdn:
            parts = self.fqdn.split(".")
            return parts[0] if parts else None
        if self.hostname:
            return self.hostname
        return None

    @property
    def display_name(self) -> str:
        """Get best display name - prefers FQDN."""
        return self.fqdn or self.hostname or self.domain or ""


class DNSRepository:
    """Repository for DNS cache persistence."""

    DEFAULT_TTL = 3600  # 1 hour

    def __init__(self, pool: "ConnectionPool", writer: "DatabaseWriter"):
        self.pool = pool
        self.writer = writer

    def get(self, ip: str) -> Optional[DNSRecord]:
        """Get cached DNS info for an IP."""
        row = self.pool.execute_read_one(
            "SELECT * FROM dns_cache WHERE ip = ? AND expires_at > ?",
            (ip, time.time())
        )
        if row:
            return self._row_to_record(row)
        return None

    def get_batch(self, ips: list[str]) -> dict[str, DNSRecord]:
        """Get cached DNS info for multiple IPs."""
        if not ips:
            return {}

        placeholders = ",".join("?" * len(ips))
        params = list(ips) + [time.time()]
        rows = self.pool.execute_read(f"""
            SELECT * FROM dns_cache
            WHERE ip IN ({placeholders}) AND expires_at > ?
        """, tuple(params))

        return {row["ip"]: self._row_to_record(row) for row in rows}

    def upsert(
        self,
        ip: str,
        hostname: Optional[str] = None,
        domain: Optional[str] = None,
        fqdn: Optional[str] = None,
        resolved: bool = True,
        ttl: float = DEFAULT_TTL,
    ) -> None:
        """Cache DNS info for an IP."""
        now = time.time()
        data = {
            "ip": ip,
            "hostname": hostname,
            "domain": domain,
            "fqdn": fqdn,
            "resolved": 1 if resolved else 0,
            "cached_at": now,
            "expires_at": now + ttl,
        }
        self.writer.queue_write(WriteOp.UPSERT_DNS_CACHE, data)

    def upsert_from_host_info(self, host_info, ttl: float = DEFAULT_TTL) -> None:
        """Cache DNS info from HostInfo object."""
        self.upsert(
            ip=host_info.ip,
            hostname=host_info.hostname,
            domain=host_info.domain,
            fqdn=host_info.fqdn,
            resolved=host_info.fqdn is not None or host_info.hostname is not None,
            ttl=ttl,
        )

    def delete(self, ip: str) -> bool:
        """Delete cached DNS info for an IP."""
        with self.pool.write_connection() as conn:
            cursor = conn.execute("DELETE FROM dns_cache WHERE ip = ?", [ip])
            conn.commit()
            return cursor.rowcount > 0

    def cleanup_expired(self) -> int:
        """Remove expired cache entries."""
        with self.pool.write_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM dns_cache WHERE expires_at < ?",
                [time.time()]
            )
            conn.commit()
            return cursor.rowcount

    def get_stats(self) -> dict:
        """Get cache statistics."""
        row = self.pool.execute_read_one("""
            SELECT
                COUNT(*) as total_entries,
                SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END) as valid_entries,
                SUM(CASE WHEN resolved = 1 THEN 1 ELSE 0 END) as resolved_entries
            FROM dns_cache
        """, (time.time(),))

        if row:
            return {
                "total_entries": row["total_entries"],
                "valid_entries": row["valid_entries"],
                "resolved_entries": row["resolved_entries"],
            }
        return {"total_entries": 0, "valid_entries": 0, "resolved_entries": 0}

    def get_top_domains(
        self,
        session_id: Optional[int] = None,
        limit: int = 10
    ) -> list[dict]:
        """Get top domains by flow count (requires join with flows)."""
        # This query needs session_id to filter flows
        if session_id is None:
            return []

        rows = self.pool.execute_read("""
            SELECT
                f.dst_domain as domain,
                COUNT(*) as flow_count,
                SUM(f.bytes_sent + f.bytes_recv) as total_bytes
            FROM flows f
            WHERE f.session_id = ? AND f.dst_domain IS NOT NULL
            GROUP BY f.dst_domain
            ORDER BY total_bytes DESC
            LIMIT ?
        """, (session_id, limit))

        return [dict(row) for row in rows]

    def _row_to_record(self, row) -> DNSRecord:
        """Convert database row to DNSRecord."""
        return DNSRecord(
            ip=row["ip"],
            hostname=row["hostname"],
            domain=row["domain"],
            fqdn=row.get("fqdn"),  # Use .get() for backward compatibility
            resolved=bool(row["resolved"]),
            cached_at=row["cached_at"],
            expires_at=row["expires_at"],
        )
