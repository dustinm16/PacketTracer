"""Database-backed path tracer that persists traceroute results."""

import time
from typing import Optional, Callable, List, TYPE_CHECKING

if TYPE_CHECKING:
    from db.connection import ConnectionPool
    from db.writer import DatabaseWriter
    from db.repositories.hop_repo import HopRepository
    from db.repositories.route_repo import RouteRepository
    from geo.resolver import GeoResolver
    from geo.dns_resolver import DNSResolver

from .path import PathTracer, TracerouteResult, HopResult


class DBPathTracer:
    """PathTracer wrapper that persists results to database.

    Maintains the same API as PathTracer but stores all traceroute
    results in the database for persistence and querying.
    """

    def __init__(
        self,
        path_tracer: PathTracer,
        hop_repo: "HopRepository",
        route_repo: "RouteRepository",
        geo_resolver: Optional["GeoResolver"] = None,
        dns_resolver: Optional["DNSResolver"] = None,
    ):
        self.path_tracer = path_tracer
        self.hop_repo = hop_repo
        self.route_repo = route_repo
        self.geo_resolver = geo_resolver
        self.dns_resolver = dns_resolver

        # Local interface IP (for path summary src_ip)
        self._local_ip: Optional[str] = None

    def set_local_ip(self, ip: str) -> None:
        """Set the local interface IP for path tracking."""
        self._local_ip = ip

    def trace(
        self,
        target: str,
        use_udp: bool = False,
        callback: Optional[Callable[[HopResult], None]] = None,
    ) -> TracerouteResult:
        """Perform a traceroute and persist results."""
        result = self.path_tracer.trace(target, use_udp, callback)
        self._persist_result(result)
        return result

    def trace_async(
        self,
        target: str,
        use_udp: bool = False,
        callback: Optional[Callable[[TracerouteResult], None]] = None,
    ) -> None:
        """Perform traceroute asynchronously and persist results."""
        def _on_complete(result: TracerouteResult):
            self._persist_result(result)
            if callback:
                callback(result)

        self.path_tracer.trace_async(target, use_udp, callback=_on_complete)

    def _persist_result(self, result: TracerouteResult) -> None:
        """Persist a traceroute result to the database."""
        # Create traceroute record
        traceroute_id = self.hop_repo.create_traceroute(
            target_ip=result.target_ip,
            target_hostname=result.target if result.target != result.target_ip else None,
        )

        # Persist each hop
        hop_ips = []
        for hop in result.hops:
            geo_data = None

            # Get geo data for hop if available
            if hop.ip and self.geo_resolver:
                geo = self.geo_resolver.get_result(hop.ip)
                if geo:
                    if isinstance(geo, dict):
                        geo_data = geo
                    else:
                        geo_data = {
                            "country": geo.country,
                            "country_code": geo.country_code,
                            "city": geo.city,
                            "isp": geo.isp,
                            "as_name": geo.as_name,
                            "as_number": geo.as_number,
                            "latitude": geo.lat,
                            "longitude": geo.lon,
                        }
                # Request async resolution for future queries
                self.geo_resolver.resolve_async(hop.ip)

            # Get DNS data
            hostname = hop.hostname
            domain = None
            if hop.ip and self.dns_resolver:
                dns_info = self.dns_resolver.get_cached(hop.ip)
                if dns_info:
                    hostname = dns_info.hostname or hostname
                    domain = dns_info.domain
                # Request async resolution
                self.dns_resolver.resolve_async(hop.ip)

            self.hop_repo.upsert_hop(
                traceroute_id=traceroute_id,
                hop_number=hop.ttl,
                ip=hop.ip,
                hostname=hostname,
                domain=domain,
                rtt=hop.avg_rtt,
                is_timeout=hop.is_timeout,
                is_target=hop.is_destination,
                geo_data=geo_data,
            )

            hop_ips.append(hop.ip or "*")

        # Mark traceroute complete
        self.hop_repo.complete_traceroute(
            traceroute_id=traceroute_id,
            total_hops=len([h for h in result.hops if h.ip]),
            reached_target=result.completed,
        )

        # Record route pattern
        if self._local_ip:
            total_latency = sum(h.avg_rtt or 0 for h in result.hops if h.avg_rtt)
            self.route_repo.record_route(
                src_ip=self._local_ip,
                dst_ip=result.target_ip,
                hop_ips=hop_ips,
                total_latency=total_latency if total_latency > 0 else None,
            )

    def get_cached(self, target: str) -> Optional[TracerouteResult]:
        """Get cached traceroute result (from in-memory cache)."""
        return self.path_tracer.get_cached(target)

    def get_traceroute_from_db(self, target_ip: str) -> Optional[dict]:
        """Get most recent traceroute for a target from database.

        Returns dict with 'traceroute' and 'hops' keys.
        """
        traces = self.hop_repo.get_traceroutes(target_ip=target_ip, limit=1)
        if not traces:
            return None

        trace = traces[0]
        hops = self.hop_repo.get_hops(trace.id)

        return {
            "traceroute": trace,
            "hops": hops,
        }

    def get_all_traceroutes(self, limit: int = 50) -> List:
        """Get all traceroutes for current session."""
        return self.hop_repo.get_traceroutes(limit=limit)

    def get_route_pattern(self, dst_ip: str) -> Optional:
        """Get current route pattern for a destination."""
        if not self._local_ip:
            return None
        return self.route_repo.get_route_pattern(self._local_ip, dst_ip)

    def get_route_history(self, dst_ip: str, limit: int = 10) -> List:
        """Get route history for a destination."""
        if not self._local_ip:
            return []
        return self.route_repo.get_route_history(self._local_ip, dst_ip, limit)

    def get_route_changes(self, dst_ip: Optional[str] = None, limit: int = 50) -> List:
        """Get recent route changes."""
        return self.route_repo.get_route_changes(
            src_ip=self._local_ip,
            dst_ip=dst_ip,
            limit=limit,
        )

    def clear_cache(self) -> None:
        """Clear in-memory cache (database records persist)."""
        self.path_tracer.clear_cache()

    # Passthrough properties
    @property
    def max_hops(self) -> int:
        return self.path_tracer.max_hops

    @property
    def timeout(self) -> float:
        return self.path_tracer.timeout

    @property
    def probes(self) -> int:
        return self.path_tracer.probes
