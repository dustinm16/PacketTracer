"""LRU cache with TTL for geo lookups."""

import time
import threading
from typing import Any, Optional, Dict
from collections import OrderedDict

from config import GEO_CACHE_SIZE, GEO_CACHE_TTL


class GeoCache:
    """Thread-safe LRU cache with TTL expiration."""

    def __init__(self, max_size: int = GEO_CACHE_SIZE, ttl: float = GEO_CACHE_TTL):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = threading.Lock()

        # Statistics
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Get a value from cache if it exists and hasn't expired."""
        with self._lock:
            if key not in self._cache:
                self.misses += 1
                return None

            value, timestamp = self._cache[key]
            if time.time() - timestamp > self.ttl:
                # Expired
                del self._cache[key]
                self.misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        """Set a value in the cache."""
        with self._lock:
            if key in self._cache:
                # Update existing
                self._cache.move_to_end(key)
            self._cache[key] = (value, time.time())

            # Evict if over capacity
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

    def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0

    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            expired_keys = [
                k for k, (_, ts) in self._cache.items() if now - ts > self.ttl
            ]
            for k in expired_keys:
                del self._cache[k]
                removed += 1
        return removed

    @property
    def size(self) -> int:
        """Current cache size."""
        with self._lock:
            return len(self._cache)

    @property
    def hit_rate(self) -> float:
        """Cache hit rate."""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": self.size,
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hit_rate,
            "ttl": self.ttl,
        }
