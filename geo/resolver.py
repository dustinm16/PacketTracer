"""Geo and ISP resolution using ip-api.com."""

import time
import threading
import requests
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Callable, Tuple, TYPE_CHECKING
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor

from config import GEO_API_URL, GEO_API_BATCH_URL, GEO_API_RATE_LIMIT
from geo.cache import GeoCache
from utils.network import is_private_ip

if TYPE_CHECKING:
    from db.repositories.geo_repo import GeoRepository

# Callback type: function that receives (ip, GeoInfo)
GeoCallback = Callable[["GeoInfo"], None]


@dataclass
class GeoInfo:
    """Geographic and ISP information for an IP."""

    ip: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    zip_code: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    isp: str = ""
    org: str = ""
    as_number: str = ""
    as_name: str = ""
    is_private: bool = False
    query_success: bool = False

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "GeoInfo":
        """Create GeoInfo from ip-api.com response."""
        if data.get("status") != "success":
            return cls(
                ip=data.get("query", ""),
                query_success=False,
            )

        # Parse AS field (format: "AS12345 Name")
        as_field = data.get("as", "")
        as_parts = as_field.split(" ", 1) if as_field else ["", ""]
        as_number = as_parts[0] if as_parts else ""
        as_name = as_parts[1] if len(as_parts) > 1 else ""

        return cls(
            ip=data.get("query", ""),
            country=data.get("country", ""),
            country_code=data.get("countryCode", ""),
            region=data.get("regionName", ""),
            city=data.get("city", ""),
            zip_code=data.get("zip", ""),
            latitude=data.get("lat", 0.0),
            longitude=data.get("lon", 0.0),
            timezone=data.get("timezone", ""),
            isp=data.get("isp", ""),
            org=data.get("org", ""),
            as_number=as_number,
            as_name=as_name,
            is_private=False,
            query_success=True,
        )

    @classmethod
    def private_ip(cls, ip: str) -> "GeoInfo":
        """Create GeoInfo for a private IP."""
        return cls(
            ip=ip,
            country="Private",
            city="Local Network",
            isp="Private Network",
            is_private=True,
            query_success=True,
        )


class GeoResolver:
    """Resolves IP addresses to geo/ISP information with rate limiting."""

    def __init__(
        self,
        cache: Optional[GeoCache] = None,
        geo_repo: Optional["GeoRepository"] = None
    ):
        self.cache = cache or GeoCache()
        self.geo_repo = geo_repo  # Optional database repository
        self._rate_limit = GEO_API_RATE_LIMIT
        self._request_times: List[float] = []
        self._lock = threading.Lock()
        # Queue now holds (ip, callback) tuples
        self._pending_queue: Queue[Tuple[str, Optional[GeoCallback]]] = Queue()
        self._results: Dict[str, GeoInfo] = {}
        self._executor = ThreadPoolExecutor(max_workers=2)
        self._batch_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        # Track pending callbacks by IP
        self._pending_callbacks: Dict[str, List[GeoCallback]] = {}

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limit."""
        now = time.time()
        with self._lock:
            # Remove requests older than 1 minute
            self._request_times = [t for t in self._request_times if now - t < 60]
            return len(self._request_times) < self._rate_limit

    def _record_request(self) -> None:
        """Record a request for rate limiting."""
        with self._lock:
            self._request_times.append(time.time())

    def _query_single(self, ip: str) -> GeoInfo:
        """Query a single IP from the API."""
        if is_private_ip(ip):
            return GeoInfo.private_ip(ip)

        # Check cache
        cached = self.cache.get(ip)
        if cached:
            return cached

        # Check rate limit
        if not self._check_rate_limit():
            # Return empty result, will be retried later
            return GeoInfo(ip=ip, query_success=False)

        try:
            self._record_request()
            url = GEO_API_URL.format(ip=ip)
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()

            geo_info = GeoInfo.from_api_response(data)
            if geo_info.query_success:
                self.cache.set(ip, geo_info)
            return geo_info

        except Exception:
            return GeoInfo(ip=ip, query_success=False)

    def _query_batch(self, ips: List[str]) -> List[GeoInfo]:
        """Query multiple IPs in a batch."""
        results = []
        to_query = []

        for ip in ips:
            if is_private_ip(ip):
                results.append(GeoInfo.private_ip(ip))
            else:
                cached = self.cache.get(ip)
                if cached:
                    results.append(cached)
                else:
                    to_query.append(ip)

        if not to_query:
            return results

        # Check rate limit (batch counts as 1 request)
        if not self._check_rate_limit():
            for ip in to_query:
                results.append(GeoInfo(ip=ip, query_success=False))
            return results

        try:
            self._record_request()
            # ip-api batch format: list of IPs
            response = requests.post(
                GEO_API_BATCH_URL,
                json=to_query[:100],  # Max 100 per batch
                timeout=10,
            )
            response.raise_for_status()
            batch_data = response.json()

            for data in batch_data:
                geo_info = GeoInfo.from_api_response(data)
                if geo_info.query_success:
                    self.cache.set(geo_info.ip, geo_info)
                results.append(geo_info)

        except Exception:
            for ip in to_query:
                results.append(GeoInfo(ip=ip, query_success=False))

        return results

    def resolve(self, ip: str) -> GeoInfo:
        """Resolve a single IP address (synchronous)."""
        return self._query_single(ip)

    def resolve_batch(self, ips: List[str]) -> Dict[str, GeoInfo]:
        """Resolve multiple IPs in batch (synchronous)."""
        results = self._query_batch(list(set(ips)))
        return {info.ip: info for info in results}

    def resolve_async(
        self,
        ip: str,
        callback: Optional[GeoCallback] = None
    ) -> None:
        """Queue an IP for async resolution with optional callback.

        Args:
            ip: IP address to resolve
            callback: Optional function to call with GeoInfo when resolved
        """
        # Check cache first - if already resolved, call callback immediately
        cached = self.cache.get(ip)
        if cached:
            if callback:
                try:
                    callback(cached)
                except Exception:
                    pass
            return

        # Check if private IP - handle immediately
        if is_private_ip(ip):
            geo_info = GeoInfo.private_ip(ip)
            if callback:
                try:
                    callback(geo_info)
                except Exception:
                    pass
            return

        # Register callback if provided
        if callback:
            with self._lock:
                if ip not in self._pending_callbacks:
                    self._pending_callbacks[ip] = []
                self._pending_callbacks[ip].append(callback)

        # Queue for background resolution
        self._pending_queue.put((ip, callback))

    def get_result(self, ip: str) -> Optional[GeoInfo]:
        """Get result for an async-resolved IP."""
        cached = self.cache.get(ip)
        if cached:
            return cached
        with self._lock:
            return self._results.get(ip)

    def start_background_resolver(self) -> None:
        """Start background thread for processing queued lookups."""
        if self._batch_thread and self._batch_thread.is_alive():
            return

        self._stop_event.clear()
        self._batch_thread = threading.Thread(
            target=self._background_resolver, daemon=True
        )
        self._batch_thread.start()

    def _background_resolver(self) -> None:
        """Background thread that processes queued lookups."""
        while not self._stop_event.is_set():
            batch_ips = []
            seen_ips = set()
            try:
                # Collect IPs for batch processing
                while len(batch_ips) < 100:
                    try:
                        item = self._pending_queue.get(timeout=0.5)
                        ip = item[0] if isinstance(item, tuple) else item
                        if ip not in seen_ips and not self.cache.get(ip) and not is_private_ip(ip):
                            batch_ips.append(ip)
                            seen_ips.add(ip)
                    except Empty:
                        break

                if batch_ips:
                    results = self._query_batch(batch_ips)
                    for info in results:
                        # Store in results dict
                        with self._lock:
                            self._results[info.ip] = info

                        # Persist to database if available
                        if self.geo_repo and info.query_success:
                            self.geo_repo.upsert_from_geo_info(info)

                        # Call all registered callbacks for this IP
                        callbacks = []
                        with self._lock:
                            if info.ip in self._pending_callbacks:
                                callbacks = self._pending_callbacks.pop(info.ip)

                        for callback in callbacks:
                            try:
                                callback(info)
                            except Exception:
                                pass

            except Exception:
                pass

            # Rate limit sleep
            time.sleep(0.1)

    def stop_background_resolver(self) -> None:
        """Stop the background resolver thread."""
        self._stop_event.set()
        if self._batch_thread:
            self._batch_thread.join(timeout=2)

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()
