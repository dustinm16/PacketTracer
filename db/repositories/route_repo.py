"""Route repository for tracking route patterns and changes."""

import time
import json
import hashlib
from typing import Optional, List, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from ..connection import ConnectionPool
    from ..writer import DatabaseWriter


@dataclass
class RoutePatternRecord:
    """Route pattern record."""
    id: int
    src_ip: str
    dst_ip: str
    path_hash: str
    hop_ips: List[str]
    hop_count: int
    times_seen: int
    first_seen: float
    last_seen: float
    avg_total_latency: Optional[float]
    min_total_latency: Optional[float]
    max_total_latency: Optional[float]
    is_stable: bool


@dataclass
class RouteChangeRecord:
    """Route change log record."""
    id: int
    src_ip: str
    dst_ip: str
    old_path_hash: Optional[str]
    new_path_hash: str
    old_hop_count: Optional[int]
    new_hop_count: int
    changed_at: float
    change_type: Optional[str]
    change_details: Optional[dict]


class RouteRepository:
    """Repository for route pattern tracking."""

    def __init__(self, pool: "ConnectionPool", writer: "DatabaseWriter"):
        self.pool = pool
        self.writer = writer

    def _compute_path_hash(self, hop_ips: List[str]) -> str:
        """Compute hash of hop IPs for path comparison."""
        path_str = "|".join(ip or "*" for ip in hop_ips)
        return hashlib.md5(path_str.encode()).hexdigest()[:16]

    def record_route(
        self,
        src_ip: str,
        dst_ip: str,
        hop_ips: List[str],
        total_latency: Optional[float] = None
    ) -> Optional[str]:
        """Record a route observation. Returns change_type if route changed."""
        path_hash = self._compute_path_hash(hop_ips)
        hop_count = len(hop_ips)
        hop_ips_json = json.dumps(hop_ips)
        now = time.time()

        # Check for existing route
        existing = self.get_route_pattern(src_ip, dst_ip)

        with self.pool.write_connection() as conn:
            # Upsert route pattern
            conn.execute("""
                INSERT INTO route_patterns (
                    src_ip, dst_ip, path_hash, hop_ips, hop_count,
                    times_seen, first_seen, last_seen,
                    avg_total_latency, min_total_latency, max_total_latency,
                    is_stable
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(src_ip, dst_ip, path_hash) DO UPDATE SET
                    times_seen = times_seen + 1,
                    last_seen = excluded.last_seen,
                    avg_total_latency = CASE
                        WHEN excluded.avg_total_latency IS NOT NULL
                        THEN (avg_total_latency * times_seen + excluded.avg_total_latency) / (times_seen + 1)
                        ELSE avg_total_latency END,
                    min_total_latency = CASE
                        WHEN excluded.min_total_latency IS NOT NULL
                        THEN MIN(min_total_latency, excluded.min_total_latency)
                        ELSE min_total_latency END,
                    max_total_latency = CASE
                        WHEN excluded.max_total_latency IS NOT NULL
                        THEN MAX(max_total_latency, excluded.max_total_latency)
                        ELSE max_total_latency END
            """, [
                src_ip, dst_ip, path_hash, hop_ips_json, hop_count,
                now, now, total_latency, total_latency, total_latency
            ])

            # Check if route changed
            change_type = None
            if existing and existing.path_hash != path_hash:
                # Route changed - log it
                change_type = self._determine_change_type(
                    existing.hop_ips, hop_ips
                )
                change_details = {
                    "old_hops": existing.hop_ips,
                    "new_hops": hop_ips,
                }

                conn.execute("""
                    INSERT INTO route_changes (
                        src_ip, dst_ip, old_path_hash, new_path_hash,
                        old_hop_count, new_hop_count, changed_at,
                        change_type, change_details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [
                    src_ip, dst_ip, existing.path_hash, path_hash,
                    existing.hop_count, hop_count, now,
                    change_type, json.dumps(change_details)
                ])

                # Mark old pattern as not current
                conn.execute("""
                    UPDATE route_patterns SET is_stable = 0
                    WHERE src_ip = ? AND dst_ip = ? AND path_hash != ?
                """, [src_ip, dst_ip, path_hash])

            elif not existing:
                # New route
                change_type = "new"
                conn.execute("""
                    INSERT INTO route_changes (
                        src_ip, dst_ip, new_path_hash, new_hop_count,
                        changed_at, change_type
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, [src_ip, dst_ip, path_hash, hop_count, now, "new"])

            conn.commit()
            return change_type

    def _determine_change_type(
        self,
        old_hops: List[str],
        new_hops: List[str]
    ) -> str:
        """Determine the type of route change."""
        old_set = set(old_hops)
        new_set = set(new_hops)

        if len(new_hops) > len(old_hops):
            return "hop_added"
        elif len(new_hops) < len(old_hops):
            return "hop_removed"
        elif old_set != new_set:
            return "hop_changed"
        else:
            return "path_shift"  # Same hops, different order

    def get_route_pattern(
        self,
        src_ip: str,
        dst_ip: str
    ) -> Optional[RoutePatternRecord]:
        """Get current route pattern for a source-destination pair."""
        row = self.pool.execute_read_one("""
            SELECT * FROM route_patterns
            WHERE src_ip = ? AND dst_ip = ? AND is_stable = 1
            ORDER BY last_seen DESC
            LIMIT 1
        """, (src_ip, dst_ip))

        if row:
            return self._row_to_pattern(row)
        return None

    def get_route_history(
        self,
        src_ip: str,
        dst_ip: str,
        limit: int = 10
    ) -> List[RoutePatternRecord]:
        """Get all route patterns seen for a pair."""
        rows = self.pool.execute_read("""
            SELECT * FROM route_patterns
            WHERE src_ip = ? AND dst_ip = ?
            ORDER BY times_seen DESC
            LIMIT ?
        """, (src_ip, dst_ip, limit))

        return [self._row_to_pattern(row) for row in rows]

    def get_route_changes(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        limit: int = 50
    ) -> List[RouteChangeRecord]:
        """Get route change history."""
        where = []
        params = []

        if src_ip:
            where.append("src_ip = ?")
            params.append(src_ip)
        if dst_ip:
            where.append("dst_ip = ?")
            params.append(dst_ip)

        where_clause = " AND ".join(where) if where else "1=1"
        params.append(limit)

        rows = self.pool.execute_read(f"""
            SELECT * FROM route_changes
            WHERE {where_clause}
            ORDER BY changed_at DESC
            LIMIT ?
        """, tuple(params))

        return [self._row_to_change(row) for row in rows]

    def get_unstable_routes(self, min_changes: int = 3) -> List[dict]:
        """Get routes that have changed frequently."""
        rows = self.pool.execute_read("""
            SELECT src_ip, dst_ip, COUNT(*) as change_count,
                   MAX(changed_at) as last_change
            FROM route_changes
            GROUP BY src_ip, dst_ip
            HAVING change_count >= ?
            ORDER BY change_count DESC
        """, (min_changes,))

        return [dict(row) for row in rows]

    def get_common_routes(self, limit: int = 20) -> List[RoutePatternRecord]:
        """Get most commonly seen routes."""
        rows = self.pool.execute_read("""
            SELECT * FROM route_patterns
            WHERE is_stable = 1
            ORDER BY times_seen DESC
            LIMIT ?
        """, (limit,))

        return [self._row_to_pattern(row) for row in rows]

    def _row_to_pattern(self, row) -> RoutePatternRecord:
        hop_ips = []
        if row["hop_ips"]:
            try:
                hop_ips = json.loads(row["hop_ips"])
            except json.JSONDecodeError:
                pass

        return RoutePatternRecord(
            id=row["id"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            path_hash=row["path_hash"],
            hop_ips=hop_ips,
            hop_count=row["hop_count"],
            times_seen=row["times_seen"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            avg_total_latency=row["avg_total_latency"],
            min_total_latency=row["min_total_latency"],
            max_total_latency=row["max_total_latency"],
            is_stable=bool(row["is_stable"]),
        )

    def _row_to_change(self, row) -> RouteChangeRecord:
        change_details = None
        if row["change_details"]:
            try:
                change_details = json.loads(row["change_details"])
            except json.JSONDecodeError:
                pass

        return RouteChangeRecord(
            id=row["id"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            old_path_hash=row["old_path_hash"],
            new_path_hash=row["new_path_hash"],
            old_hop_count=row["old_hop_count"],
            new_hop_count=row["new_hop_count"],
            changed_at=row["changed_at"],
            change_type=row["change_type"],
            change_details=change_details,
        )
