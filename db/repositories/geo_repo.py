"""Geo repository for geo cache persistence."""

import time
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from ..connection import ConnectionPool
    from ..writer import DatabaseWriter

from ..writer import WriteOp


@dataclass
class GeoRecord:
    """Cached geo information for an IP."""
    ip: str
    country: Optional[str]
    country_code: Optional[str]
    region: Optional[str]
    city: Optional[str]
    zip_code: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    timezone: Optional[str]
    isp: Optional[str]
    org: Optional[str]
    as_number: Optional[str]
    as_name: Optional[str]
    is_private: bool
    query_success: bool
    cached_at: float
    expires_at: float

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def location_str(self) -> str:
        """Format location as string."""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.country:
            parts.append(self.country)
        return ", ".join(parts) if parts else "Unknown"

    def to_dict(self) -> dict:
        """Convert to dictionary for compatibility."""
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "zip_code": self.zip_code,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "isp": self.isp,
            "org": self.org,
            "as_number": self.as_number,
            "as_name": self.as_name,
            "is_private": self.is_private,
            "query_success": self.query_success,
        }


class GeoRepository:
    """Repository for geo cache persistence."""

    DEFAULT_TTL = 86400  # 24 hours

    def __init__(self, pool: "ConnectionPool", writer: "DatabaseWriter"):
        self.pool = pool
        self.writer = writer

    def get(self, ip: str) -> Optional[GeoRecord]:
        """Get cached geo info for an IP."""
        row = self.pool.execute_read_one(
            "SELECT * FROM geo_cache WHERE ip = ? AND expires_at > ?",
            (ip, time.time())
        )
        if row:
            return self._row_to_record(row)
        return None

    def get_batch(self, ips: list[str]) -> dict[str, GeoRecord]:
        """Get cached geo info for multiple IPs."""
        if not ips:
            return {}

        placeholders = ",".join("?" * len(ips))
        params = list(ips) + [time.time()]
        rows = self.pool.execute_read(f"""
            SELECT * FROM geo_cache
            WHERE ip IN ({placeholders}) AND expires_at > ?
        """, tuple(params))

        return {row["ip"]: self._row_to_record(row) for row in rows}

    def upsert(
        self,
        ip: str,
        country: Optional[str] = None,
        country_code: Optional[str] = None,
        region: Optional[str] = None,
        city: Optional[str] = None,
        zip_code: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        timezone: Optional[str] = None,
        isp: Optional[str] = None,
        org: Optional[str] = None,
        as_number: Optional[str] = None,
        as_name: Optional[str] = None,
        is_private: bool = False,
        query_success: bool = True,
        ttl: float = DEFAULT_TTL,
    ) -> None:
        """Cache geo info for an IP."""
        now = time.time()
        data = {
            "ip": ip,
            "country": country,
            "country_code": country_code,
            "region": region,
            "city": city,
            "zip_code": zip_code,
            "latitude": latitude,
            "longitude": longitude,
            "timezone": timezone,
            "isp": isp,
            "org": org,
            "as_number": as_number,
            "as_name": as_name,
            "is_private": 1 if is_private else 0,
            "query_success": 1 if query_success else 0,
            "cached_at": now,
            "expires_at": now + ttl,
        }
        self.writer.queue_write(WriteOp.UPSERT_GEO_CACHE, data)

    def upsert_from_geo_info(self, geo_info, ttl: float = DEFAULT_TTL) -> None:
        """Cache geo info from GeoInfo object."""
        self.upsert(
            ip=geo_info.ip,
            country=geo_info.country,
            country_code=geo_info.country_code,
            region=geo_info.region,
            city=geo_info.city,
            zip_code=geo_info.zip_code,
            latitude=geo_info.latitude,
            longitude=geo_info.longitude,
            timezone=geo_info.timezone,
            isp=geo_info.isp,
            org=geo_info.org,
            as_number=geo_info.as_number,
            as_name=geo_info.as_name,
            is_private=geo_info.is_private,
            query_success=geo_info.query_success,
            ttl=ttl,
        )

    def delete(self, ip: str) -> bool:
        """Delete cached geo info for an IP."""
        with self.pool.write_connection() as conn:
            cursor = conn.execute("DELETE FROM geo_cache WHERE ip = ?", [ip])
            conn.commit()
            return cursor.rowcount > 0

    def cleanup_expired(self) -> int:
        """Remove expired cache entries."""
        with self.pool.write_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM geo_cache WHERE expires_at < ?",
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
                SUM(CASE WHEN query_success = 1 THEN 1 ELSE 0 END) as successful_lookups
            FROM geo_cache
        """, (time.time(),))

        if row:
            return {
                "total_entries": row["total_entries"],
                "valid_entries": row["valid_entries"],
                "successful_lookups": row["successful_lookups"],
            }
        return {"total_entries": 0, "valid_entries": 0, "successful_lookups": 0}

    def _row_to_record(self, row) -> GeoRecord:
        """Convert database row to GeoRecord."""
        return GeoRecord(
            ip=row["ip"],
            country=row["country"],
            country_code=row["country_code"],
            region=row["region"],
            city=row["city"],
            zip_code=row["zip_code"],
            latitude=row["latitude"],
            longitude=row["longitude"],
            timezone=row["timezone"],
            isp=row["isp"],
            org=row["org"],
            as_number=row["as_number"],
            as_name=row["as_name"],
            is_private=bool(row["is_private"]),
            query_success=bool(row["query_success"]),
            cached_at=row["cached_at"],
            expires_at=row["expires_at"],
        )
