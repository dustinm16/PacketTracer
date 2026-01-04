"""Tests for utils/network.py module."""

import pytest
from utils.network import (
    is_private_ip,
    format_bytes,
    format_packets,
    get_local_ip,
    is_api_traffic,
    add_filtered_ip,
)


class TestIsPrivateIp:
    """Tests for is_private_ip function."""

    def test_private_class_a(self):
        """Test 10.x.x.x private range."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_private_class_b(self):
        """Test 172.16-31.x.x private range."""
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True

    def test_private_class_c(self):
        """Test 192.168.x.x private range."""
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.255") is True

    def test_loopback(self):
        """Test loopback addresses."""
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("127.255.255.255") is True

    def test_link_local(self):
        """Test link-local addresses (169.254.x.x)."""
        assert is_private_ip("169.254.0.1") is True
        assert is_private_ip("169.254.255.255") is True

    def test_multicast(self):
        """Test multicast addresses (224.x.x.x - 239.x.x.x)."""
        assert is_private_ip("224.0.0.1") is True
        assert is_private_ip("239.255.255.255") is True

    def test_public_ips(self):
        """Test public IP addresses."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("208.67.222.222") is False

    def test_invalid_ip(self):
        """Test invalid IP addresses return True (fail-safe)."""
        assert is_private_ip("not.an.ip") is True
        assert is_private_ip("256.256.256.256") is True
        assert is_private_ip("") is True


class TestFormatBytes:
    """Tests for format_bytes function."""

    def test_bytes(self):
        """Test bytes formatting."""
        assert format_bytes(0) == "0.0 B"
        assert format_bytes(100) == "100.0 B"
        assert format_bytes(1023) == "1023.0 B"

    def test_kilobytes(self):
        """Test kilobytes formatting."""
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(1536) == "1.5 KB"
        assert format_bytes(102400) == "100.0 KB"

    def test_megabytes(self):
        """Test megabytes formatting."""
        assert format_bytes(1048576) == "1.0 MB"
        assert format_bytes(1572864) == "1.5 MB"

    def test_gigabytes(self):
        """Test gigabytes formatting."""
        assert format_bytes(1073741824) == "1.0 GB"
        assert format_bytes(1610612736) == "1.5 GB"

    def test_terabytes(self):
        """Test terabytes formatting."""
        assert format_bytes(1099511627776) == "1.0 TB"


class TestFormatPackets:
    """Tests for format_packets function."""

    def test_small_numbers(self):
        """Test small packet counts."""
        assert format_packets(0) == "0"
        assert format_packets(999) == "999"

    def test_thousands(self):
        """Test thousands (K suffix)."""
        assert format_packets(1000) == "1.0K"
        assert format_packets(1500) == "1.5K"
        assert format_packets(999999) == "1000.0K"

    def test_millions(self):
        """Test millions (M suffix)."""
        assert format_packets(1000000) == "1.0M"
        assert format_packets(1500000) == "1.5M"


class TestGetLocalIp:
    """Tests for get_local_ip function."""

    @pytest.mark.requires_network
    def test_returns_valid_ip(self):
        """Test that a valid IP is returned."""
        ip = get_local_ip()
        if ip:  # May be None in some environments
            # Should be a valid IPv4 address
            parts = ip.split(".")
            assert len(parts) == 4
            for part in parts:
                assert 0 <= int(part) <= 255


class TestApiTrafficFiltering:
    """Tests for API traffic filtering."""

    def test_add_filtered_ip(self):
        """Test adding IP to filter list."""
        add_filtered_ip("1.2.3.4")
        assert is_api_traffic("1.2.3.4") is True

    def test_non_filtered_ip(self):
        """Test that random IPs are not filtered."""
        # Most random IPs shouldn't be filtered
        # (unless they happen to be ip-api.com IPs)
        assert is_api_traffic("192.168.1.1") is False
