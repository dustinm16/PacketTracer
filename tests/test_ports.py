"""Tests for tracking/ports.py module."""

import time
import pytest
from tracking.ports import (
    PortTracker,
    PortStats,
    ScanActivity,
    KNOWN_SERVICES,
)


class TestPortStats:
    """Tests for PortStats dataclass."""

    def test_creation(self):
        """Test basic PortStats creation."""
        stats = PortStats(port=443, protocol="TCP")
        assert stats.port == 443
        assert stats.protocol == "TCP"
        assert stats.packets_in == 0
        assert stats.packets_out == 0

    def test_total_packets(self):
        """Test total_packets property."""
        stats = PortStats(port=443, packets_in=100, packets_out=50)
        assert stats.total_packets == 150

    def test_total_bytes(self):
        """Test total_bytes property."""
        stats = PortStats(port=443, bytes_in=10000, bytes_out=5000)
        assert stats.total_bytes == 15000

    def test_unique_sources(self):
        """Test unique_sources property."""
        stats = PortStats(port=443)
        stats.src_ips.add("192.168.1.1")
        stats.src_ips.add("192.168.1.2")
        stats.src_ips.add("192.168.1.3")
        assert stats.unique_sources == 3

    def test_unique_destinations(self):
        """Test unique_destinations property."""
        stats = PortStats(port=443)
        stats.dst_ips.add("8.8.8.8")
        stats.dst_ips.add("8.8.4.4")
        assert stats.unique_destinations == 2

    def test_activity_duration(self):
        """Test activity_duration property."""
        now = time.time()
        stats = PortStats(port=443, first_seen=now - 60, last_seen=now)
        assert stats.activity_duration == 60

    def test_packets_per_second(self):
        """Test packets_per_second property."""
        now = time.time()
        stats = PortStats(
            port=443,
            packets_in=100,
            packets_out=100,
            first_seen=now - 10,
            last_seen=now,
        )
        assert stats.packets_per_second == 20.0  # 200 packets / 10 seconds

    def test_bytes_per_second(self):
        """Test bytes_per_second property."""
        now = time.time()
        stats = PortStats(
            port=443,
            bytes_in=5000,
            bytes_out=5000,
            first_seen=now - 10,
            last_seen=now,
        )
        assert stats.bytes_per_second == 1000.0  # 10000 bytes / 10 seconds


class TestScanActivity:
    """Tests for ScanActivity dataclass."""

    def test_creation(self):
        """Test basic ScanActivity creation."""
        activity = ScanActivity(src_ip="192.168.1.100")
        assert activity.src_ip == "192.168.1.100"
        assert activity.unique_ports == 0

    def test_unique_ports(self):
        """Test unique_ports property."""
        activity = ScanActivity(src_ip="192.168.1.100")
        activity.ports_hit.add(22)
        activity.ports_hit.add(80)
        activity.ports_hit.add(443)
        assert activity.unique_ports == 3

    def test_scan_rate(self):
        """Test scan_rate calculation."""
        now = time.time()
        activity = ScanActivity(
            src_ip="192.168.1.100",
            first_seen=now - 10,
            last_seen=now,
        )
        activity.ports_hit = {22, 80, 443, 8080, 3389}  # 5 ports
        assert activity.scan_rate == 0.5  # 5 ports / 10 seconds

    def test_is_likely_scan_false(self):
        """Test is_likely_scan returns False for normal traffic."""
        activity = ScanActivity(src_ip="192.168.1.100")
        activity.ports_hit = {22, 80, 443}  # Only 3 ports
        assert activity.is_likely_scan is False

    def test_is_likely_scan_true(self):
        """Test is_likely_scan returns True for scanning behavior."""
        now = time.time()
        activity = ScanActivity(
            src_ip="192.168.1.100",
            first_seen=now - 10,
            last_seen=now,
        )
        # Add many ports quickly
        activity.ports_hit = set(range(1, 20))  # 19 ports in 10 seconds
        assert activity.is_likely_scan is True


class TestKnownServices:
    """Tests for KNOWN_SERVICES constant."""

    def test_common_ports_defined(self):
        """Test that common ports are in KNOWN_SERVICES."""
        assert 22 in KNOWN_SERVICES  # SSH
        assert 80 in KNOWN_SERVICES  # HTTP
        assert 443 in KNOWN_SERVICES  # HTTPS
        assert 53 in KNOWN_SERVICES  # DNS
        assert 3306 in KNOWN_SERVICES  # MySQL

    def test_service_format(self):
        """Test that services are tuples of (name, description)."""
        for port, service in KNOWN_SERVICES.items():
            assert isinstance(service, tuple)
            assert len(service) == 2
            assert isinstance(service[0], str)  # Name
            assert isinstance(service[1], str)  # Description


class TestPortTracker:
    """Tests for PortTracker class."""

    def test_creation(self, port_tracker):
        """Test PortTracker creation."""
        assert port_tracker.max_ports == 100
        assert port_tracker.scan_window == 60

    def test_record_packet_creates_stats(self, port_tracker):
        """Test that recording a packet creates port stats."""
        port_tracker.record_packet(
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            length=1000,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
        )

        stats = port_tracker.get_port_stats(443, "TCP")
        assert stats is not None
        assert stats.packets_in == 1
        assert stats.bytes_in == 1000

    def test_record_packet_updates_stats(self, port_tracker):
        """Test that recording packets updates existing stats."""
        for _ in range(5):
            port_tracker.record_packet(
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                length=100,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
            )

        stats = port_tracker.get_port_stats(443, "TCP")
        assert stats.packets_in == 5
        assert stats.bytes_in == 500

    def test_tracks_both_ports(self, port_tracker):
        """Test that both source and destination ports are tracked."""
        port_tracker.record_packet(
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            length=100,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
        )

        dst_stats = port_tracker.get_port_stats(443, "TCP")
        src_stats = port_tracker.get_port_stats(54321, "TCP")

        assert dst_stats is not None
        assert src_stats is not None

    def test_tracks_unique_ips(self, port_tracker):
        """Test tracking of unique source IPs."""
        for i in range(5):
            port_tracker.record_packet(
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                length=100,
                src_ip=f"192.168.1.{i}",
                dst_ip="8.8.8.8",
            )

        stats = port_tracker.get_port_stats(443, "TCP")
        assert stats.unique_sources == 5

    def test_hit_count_tracking(self, port_tracker):
        """Test hit_count tracks unique source IPs per port."""
        # Same IP hitting port multiple times
        for _ in range(5):
            port_tracker.record_packet(
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                length=100,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
            )

        stats = port_tracker.get_port_stats(443, "TCP")
        assert stats.hit_count == 1  # Only one unique source

        # Different IPs hitting same port
        for i in range(3):
            port_tracker.record_packet(
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                length=100,
                src_ip=f"192.168.1.{i + 1}",
                dst_ip="8.8.8.8",
            )

        stats = port_tracker.get_port_stats(443, "TCP")
        assert stats.hit_count == 4  # 1 + 3 unique sources

    def test_get_top_ports_by_bytes(self, port_tracker):
        """Test get_top_ports sorted by bytes."""
        # Use unique src_ports to avoid them being tracked together
        ports_data = [(1001, 443, 10000), (1002, 80, 5000), (1003, 22, 15000)]
        for src_port, dst_port, bytes_val in ports_data:
            port_tracker.record_packet(
                src_port=src_port,
                dst_port=dst_port,
                protocol="TCP",
                length=bytes_val,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
            )

        top = port_tracker.get_top_ports(n=10, by="bytes")
        # Filter to just destination ports (well-known)
        dst_ports = [p for p in top if p.port in [443, 80, 22]]
        assert len(dst_ports) == 3
        # Should be sorted by bytes descending
        assert dst_ports[0].port == 22  # 15000
        assert dst_ports[1].port == 443  # 10000
        assert dst_ports[2].port == 80  # 5000

    def test_get_top_ports_by_packets(self, port_tracker):
        """Test get_top_ports sorted by packets."""
        # Use unique src_ports for each dest to isolate tracking
        for src_port, dst_port, count in [(1001, 443, 10), (1002, 80, 5), (1003, 22, 15)]:
            for _ in range(count):
                port_tracker.record_packet(
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="TCP",
                    length=100,
                    src_ip="192.168.1.100",
                    dst_ip="8.8.8.8",
                )

        top = port_tracker.get_top_ports(n=10, by="packets")
        # Filter to just destination ports (well-known)
        dst_ports = [p for p in top if p.port in [443, 80, 22]]
        assert dst_ports[0].port == 22  # 15 packets

    def test_get_service_name(self, port_tracker):
        """Test get_service_name returns known services."""
        name, desc = port_tracker.get_service_name(443)
        assert name == "HTTPS"
        assert desc == "Secure Web"

        name, desc = port_tracker.get_service_name(9999)
        assert name == "Unknown"

    def test_get_active_ports(self, port_tracker):
        """Test get_active_ports filters by time."""
        port_tracker.record_packet(
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            length=100,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
        )

        active = port_tracker.get_active_ports(seconds=60)
        assert len(active) >= 1

    def test_scan_activity_detection(self, port_tracker):
        """Test detection of port scanning activity."""
        # Simulate port scan - many ports from same IP
        for port in range(1, 20):
            port_tracker.record_packet(
                src_port=54321,
                dst_port=port,
                protocol="TCP",
                length=64,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
            )

        scan_activity = port_tracker.get_scan_activity(min_ports=10)
        assert len(scan_activity) >= 1
        assert scan_activity[0].src_ip == "192.168.1.100"
        assert scan_activity[0].unique_ports >= 10

    def test_get_likely_scanners(self, port_tracker):
        """Test get_likely_scanners identifies port scanners."""
        # Simulate aggressive port scan
        for port in range(1, 50):
            port_tracker.record_packet(
                src_port=54321,
                dst_port=port,
                protocol="TCP",
                length=64,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
            )

        scanners = port_tracker.get_likely_scanners()
        # Should detect as likely scanner (>10 ports, high rate)
        assert len(scanners) >= 1

    def test_get_top_hit_ports(self, port_tracker):
        """Test get_top_hit_ports returns most targeted ports."""
        # Multiple IPs hitting port 443
        for i in range(10):
            port_tracker.record_packet(
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                length=100,
                src_ip=f"192.168.1.{i}",
                dst_ip="8.8.8.8",
            )

        # Fewer IPs hitting port 80
        for i in range(3):
            port_tracker.record_packet(
                src_port=54321,
                dst_port=80,
                protocol="TCP",
                length=100,
                src_ip=f"192.168.2.{i}",
                dst_ip="8.8.8.8",
            )

        top_hit = port_tracker.get_top_hit_ports(n=2)
        assert len(top_hit) >= 2
        assert top_hit[0].hit_count >= top_hit[1].hit_count

    def test_get_summary(self, port_tracker):
        """Test get_summary returns correct totals."""
        for _ in range(5):
            port_tracker.record_packet(
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                length=1000,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
            )

        summary = port_tracker.get_summary()
        assert "total_ports" in summary
        assert "total_bytes" in summary
        assert "total_packets" in summary
        assert summary["total_bytes"] >= 5000

    def test_clear(self, port_tracker):
        """Test clear removes all tracking data."""
        port_tracker.record_packet(
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            length=100,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
        )

        port_tracker.clear()

        assert port_tracker.get_port_stats(443, "TCP") is None
        assert len(port_tracker.get_scan_activity()) == 0

    def test_pruning(self):
        """Test that ports are pruned when exceeding max."""
        tracker = PortTracker(max_ports=10, scan_window=60)

        # Add more ports than max
        for port in range(1, 20):
            tracker.record_packet(
                src_port=54321,
                dst_port=port,
                protocol="TCP",
                length=100,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
            )

        summary = tracker.get_summary()
        # After pruning, should have fewer ports
        assert summary["total_ports"] <= 10
