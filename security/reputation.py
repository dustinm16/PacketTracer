"""IP Reputation checking using threat intelligence feeds."""

import time
import threading
import logging
import requests
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Callable, Set
from enum import Enum
from collections import OrderedDict
from queue import Queue

from utils.network import is_private_ip

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat level classification."""
    UNKNOWN = 0
    CLEAN = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class ReputationResult:
    """Result of an IP reputation check."""
    ip: str
    threat_level: ThreatLevel
    confidence_score: int  # 0-100, AbuseIPDB confidence
    total_reports: int
    last_reported: Optional[float]  # Timestamp
    categories: List[str]  # Attack categories
    isp: str = ""
    domain: str = ""
    country_code: str = ""
    is_tor: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    cached_at: float = field(default_factory=time.time)

    @property
    def is_malicious(self) -> bool:
        """Check if IP is considered malicious."""
        return self.threat_level.value >= ThreatLevel.MEDIUM.value

    @property
    def is_suspicious(self) -> bool:
        """Check if IP is suspicious (low threat or higher)."""
        return self.threat_level.value >= ThreatLevel.LOW.value


# AbuseIPDB category codes
ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class ReputationChecker:
    """Check IP reputation using AbuseIPDB and other sources."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_size: int = 10000,
        cache_ttl: float = 86400,  # 24 hours
        rate_limit: int = 1000,  # Requests per day (AbuseIPDB free tier)
        callback: Optional[Callable[[ReputationResult], None]] = None,
    ):
        self.api_key = api_key
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.rate_limit = rate_limit
        self.callback = callback

        # Cache: ip -> (result, timestamp)
        self._cache: OrderedDict[str, ReputationResult] = OrderedDict()
        self._cache_lock = threading.Lock()

        # Rate limiting
        self._requests_today = 0
        self._rate_reset_time = time.time() + 86400

        # Background processing
        self._queue: Queue[str] = Queue()
        self._pending: Set[str] = set()
        self._pending_lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Statistics
        self.checks_total = 0
        self.checks_cached = 0
        self.checks_api = 0
        self.malicious_found = 0

    def start(self) -> None:
        """Start background reputation checker."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._background_worker, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop background checker."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def check_ip(self, ip: str, async_check: bool = True) -> Optional[ReputationResult]:
        """Check IP reputation.

        Args:
            ip: IP address to check
            async_check: If True, queue for background processing and return cached result
                        If False, perform synchronous check

        Returns:
            ReputationResult if cached or sync check, None if queued for async
        """
        # Skip private IPs
        if is_private_ip(ip):
            return ReputationResult(
                ip=ip,
                threat_level=ThreatLevel.CLEAN,
                confidence_score=0,
                total_reports=0,
                last_reported=None,
                categories=[],
            )

        self.checks_total += 1

        # Check cache first
        cached = self._get_cached(ip)
        if cached:
            self.checks_cached += 1
            return cached

        if async_check:
            # Queue for background processing
            self._queue_ip(ip)
            return None
        else:
            # Synchronous check
            return self._check_ip_sync(ip)

    def check_ips(self, ips: List[str]) -> Dict[str, Optional[ReputationResult]]:
        """Check multiple IPs, returning cached results immediately."""
        results = {}
        for ip in ips:
            results[ip] = self.check_ip(ip, async_check=True)
        return results

    def get_cached(self, ip: str) -> Optional[ReputationResult]:
        """Get cached result without triggering a check."""
        return self._get_cached(ip)

    def get_malicious_ips(self) -> List[ReputationResult]:
        """Get all cached IPs flagged as malicious."""
        with self._cache_lock:
            return [r for r in self._cache.values() if r.is_malicious]

    def get_suspicious_ips(self) -> List[ReputationResult]:
        """Get all cached IPs flagged as suspicious."""
        with self._cache_lock:
            return [r for r in self._cache.values() if r.is_suspicious]

    def _get_cached(self, ip: str) -> Optional[ReputationResult]:
        """Get cached result if valid."""
        with self._cache_lock:
            if ip in self._cache:
                result = self._cache[ip]
                if time.time() - result.cached_at < self.cache_ttl:
                    self._cache.move_to_end(ip)
                    return result
                else:
                    del self._cache[ip]
        return None

    def _cache_result(self, result: ReputationResult) -> None:
        """Cache a reputation result."""
        with self._cache_lock:
            self._cache[result.ip] = result
            self._cache.move_to_end(result.ip)

            # Evict oldest if over capacity
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)

    def _queue_ip(self, ip: str) -> None:
        """Queue IP for background checking."""
        with self._pending_lock:
            if ip not in self._pending:
                self._pending.add(ip)
                self._queue.put(ip)

    def _background_worker(self) -> None:
        """Background worker for async reputation checks."""
        while self._running:
            try:
                ip = self._queue.get(timeout=1.0)
                with self._pending_lock:
                    self._pending.discard(ip)

                # Skip if already cached (may have been checked while in queue)
                if self._get_cached(ip):
                    continue

                result = self._check_ip_sync(ip)
                if result and self.callback:
                    self.callback(result)

            except Exception as e:
                # Queue.get timeout is expected, don't log it
                if "Empty" not in type(e).__name__:
                    logger.debug(f"Error in reputation background worker: {e}")
                continue

    def _check_ip_sync(self, ip: str) -> Optional[ReputationResult]:
        """Perform synchronous IP reputation check."""
        # Check rate limit
        if not self._check_rate_limit():
            return None

        if not self.api_key:
            # No API key, return unknown
            result = ReputationResult(
                ip=ip,
                threat_level=ThreatLevel.UNKNOWN,
                confidence_score=0,
                total_reports=0,
                last_reported=None,
                categories=[],
            )
            self._cache_result(result)
            return result

        try:
            result = self._query_abuseipdb(ip)
            if result:
                self.checks_api += 1
                self._cache_result(result)
                if result.is_malicious:
                    self.malicious_found += 1
                return result
        except requests.RequestException as e:
            logger.warning(f"AbuseIPDB API request failed for {ip}: {e}")
        except (KeyError, ValueError, TypeError) as e:
            logger.warning(f"Failed to parse AbuseIPDB response for {ip}: {e}")

        return None

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = time.time()
        if now > self._rate_reset_time:
            self._requests_today = 0
            self._rate_reset_time = now + 86400

        if self._requests_today >= self.rate_limit:
            return False

        self._requests_today += 1
        return True

    def _query_abuseipdb(self, ip: str) -> Optional[ReputationResult]:
        """Query AbuseIPDB API."""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True,
        }

        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()

        data = response.json().get("data", {})

        # Parse categories from reports
        categories = []
        for report in data.get("reports", [])[:10]:  # Last 10 reports
            for cat_id in report.get("categories", []):
                cat_name = ABUSEIPDB_CATEGORIES.get(cat_id)
                if cat_name and cat_name not in categories:
                    categories.append(cat_name)

        # Determine threat level based on confidence score
        confidence = data.get("abuseConfidenceScore", 0)
        if confidence == 0:
            threat_level = ThreatLevel.CLEAN
        elif confidence < 25:
            threat_level = ThreatLevel.LOW
        elif confidence < 50:
            threat_level = ThreatLevel.MEDIUM
        elif confidence < 75:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.CRITICAL

        # Parse last reported time
        last_reported = None
        if data.get("lastReportedAt"):
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(data["lastReportedAt"].replace("Z", "+00:00"))
                last_reported = dt.timestamp()
            except Exception:
                pass

        return ReputationResult(
            ip=ip,
            threat_level=threat_level,
            confidence_score=confidence,
            total_reports=data.get("totalReports", 0),
            last_reported=last_reported,
            categories=categories,
            isp=data.get("isp", ""),
            domain=data.get("domain", ""),
            country_code=data.get("countryCode", ""),
            is_tor=data.get("isTor", False),
            is_vpn="VPN IP" in categories,
            is_proxy=data.get("isProxy", False) or "Open Proxy" in categories,
            is_datacenter=data.get("usageType", "").lower() in ["data center", "hosting"],
        )

    def get_stats(self) -> Dict:
        """Get checker statistics."""
        with self._cache_lock:
            cache_size = len(self._cache)

        return {
            "cache_size": cache_size,
            "checks_total": self.checks_total,
            "checks_cached": self.checks_cached,
            "checks_api": self.checks_api,
            "malicious_found": self.malicious_found,
            "requests_remaining": max(0, self.rate_limit - self._requests_today),
            "has_api_key": bool(self.api_key),
        }

    def clear_cache(self) -> None:
        """Clear the reputation cache."""
        with self._cache_lock:
            self._cache.clear()
