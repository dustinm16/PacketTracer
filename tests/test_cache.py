"""Tests for geo/cache.py module."""

import time
import pytest
from geo.cache import GeoCache


class TestGeoCache:
    """Tests for GeoCache class."""

    def test_creation(self, geo_cache):
        """Test cache creation."""
        assert geo_cache.max_size == 100
        assert geo_cache.ttl == 60
        assert geo_cache.size == 0

    def test_set_and_get(self, geo_cache):
        """Test basic set and get operations."""
        geo_cache.set("8.8.8.8", {"country": "US", "city": "Mountain View"})

        result = geo_cache.get("8.8.8.8")
        assert result is not None
        assert result["country"] == "US"
        assert result["city"] == "Mountain View"

    def test_get_missing_key(self, geo_cache):
        """Test get returns None for missing key."""
        result = geo_cache.get("nonexistent")
        assert result is None

    def test_get_updates_lru(self, geo_cache):
        """Test that get moves item to end (LRU behavior)."""
        geo_cache.set("key1", "value1")
        geo_cache.set("key2", "value2")

        # Access key1 to make it most recently used
        geo_cache.get("key1")

        # Add items to force eviction
        geo_cache.max_size = 2
        geo_cache.set("key3", "value3")

        # key2 should be evicted (least recently used), key1 should remain
        assert geo_cache.get("key1") == "value1"
        assert geo_cache.get("key2") is None

    def test_ttl_expiration(self):
        """Test that items expire after TTL."""
        cache = GeoCache(max_size=100, ttl=0.1)  # 100ms TTL

        cache.set("key", "value")
        assert cache.get("key") == "value"

        time.sleep(0.15)  # Wait for expiration

        assert cache.get("key") is None

    def test_delete(self, geo_cache):
        """Test delete operation."""
        geo_cache.set("key", "value")
        assert geo_cache.get("key") == "value"

        result = geo_cache.delete("key")
        assert result is True
        assert geo_cache.get("key") is None

    def test_delete_missing(self, geo_cache):
        """Test delete returns False for missing key."""
        result = geo_cache.delete("nonexistent")
        assert result is False

    def test_clear(self):
        """Test clear removes all entries."""
        # Use fresh cache to avoid state from other tests
        from geo.cache import GeoCache
        cache = GeoCache(max_size=100, ttl=60)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.get("key1")  # 1 hit
        cache.get("missing")  # 1 miss

        cache.clear()

        # Check stats were reset
        assert cache.size == 0
        assert cache.hits == 0
        assert cache.misses == 0

        # Getting cleared keys will register new misses (after stats were reset)
        assert cache.get("key1") is None
        assert cache.get("key2") is None
        assert cache.misses == 2  # New misses after clear

    def test_size_property(self, geo_cache):
        """Test size property."""
        assert geo_cache.size == 0

        geo_cache.set("key1", "value1")
        assert geo_cache.size == 1

        geo_cache.set("key2", "value2")
        assert geo_cache.size == 2

        geo_cache.delete("key1")
        assert geo_cache.size == 1

    def test_max_size_eviction(self):
        """Test that oldest items are evicted when max size is exceeded."""
        cache = GeoCache(max_size=3, ttl=3600)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        cache.set("key4", "value4")  # Should evict key1

        assert cache.size == 3
        assert cache.get("key1") is None  # Evicted
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"

    def test_update_existing_key(self, geo_cache):
        """Test updating an existing key."""
        geo_cache.set("key", "value1")
        geo_cache.set("key", "value2")

        assert geo_cache.get("key") == "value2"
        assert geo_cache.size == 1  # Should not increase size

    def test_hits_and_misses(self, geo_cache):
        """Test hit/miss tracking."""
        geo_cache.set("key", "value")

        geo_cache.get("key")  # Hit
        geo_cache.get("key")  # Hit
        geo_cache.get("missing")  # Miss

        assert geo_cache.hits == 2
        assert geo_cache.misses == 1

    def test_hit_rate(self, geo_cache):
        """Test hit_rate calculation."""
        geo_cache.set("key", "value")

        geo_cache.get("key")  # Hit
        geo_cache.get("key")  # Hit
        geo_cache.get("missing")  # Miss
        geo_cache.get("missing2")  # Miss

        assert geo_cache.hit_rate == 0.5  # 2 hits / 4 total

    def test_hit_rate_empty(self, geo_cache):
        """Test hit_rate with no requests."""
        assert geo_cache.hit_rate == 0.0

    def test_cleanup_expired(self):
        """Test cleanup_expired removes old entries."""
        cache = GeoCache(max_size=100, ttl=0.1)

        cache.set("key1", "value1")
        cache.set("key2", "value2")

        time.sleep(0.15)  # Wait for expiration

        cache.set("key3", "value3")  # Add fresh entry

        removed = cache.cleanup_expired()

        assert removed == 2
        assert cache.size == 1
        assert cache.get("key3") == "value3"

    def test_get_stats(self, geo_cache):
        """Test get_stats returns all statistics."""
        geo_cache.set("key", "value")
        geo_cache.get("key")
        geo_cache.get("missing")

        stats = geo_cache.get_stats()

        assert "size" in stats
        assert "max_size" in stats
        assert "hits" in stats
        assert "misses" in stats
        assert "hit_rate" in stats
        assert "ttl" in stats

        assert stats["size"] == 1
        assert stats["max_size"] == 100
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5

    def test_thread_safety(self, geo_cache):
        """Test basic thread safety with concurrent access."""
        import threading

        def writer():
            for i in range(100):
                geo_cache.set(f"key{i}", f"value{i}")

        def reader():
            for i in range(100):
                geo_cache.get(f"key{i}")

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should not raise any exceptions
        assert geo_cache.size <= 100  # Some entries may have been evicted

    def test_complex_values(self, geo_cache):
        """Test storing complex values."""
        complex_value = {
            "country": "US",
            "city": "San Francisco",
            "region": "California",
            "isp": "Google LLC",
            "coords": {"lat": 37.7749, "lon": -122.4194},
            "tags": ["cloud", "google", "dns"],
        }

        geo_cache.set("8.8.8.8", complex_value)
        result = geo_cache.get("8.8.8.8")

        assert result == complex_value
        assert result["coords"]["lat"] == 37.7749
        assert "cloud" in result["tags"]
