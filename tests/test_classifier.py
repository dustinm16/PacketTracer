"""Tests for tracking/classifier.py module."""

import time
import pytest
from tracking.classifier import (
    TrafficClassifier,
    TrafficCategory,
    TrafficClassification,
)
from tracking.flow import Flow


class TestTrafficCategory:
    """Tests for TrafficCategory enum."""

    def test_all_categories_exist(self):
        """Test that all expected categories are defined."""
        expected = [
            "WEB_BROWSING", "VIDEO_STREAMING", "AUDIO_STREAMING",
            "GAMING", "VOIP", "FILE_TRANSFER", "EMAIL", "DNS",
            "DATABASE", "REMOTE_ACCESS", "VPN_TUNNEL", "P2P",
            "ENCRYPTED", "IOT", "NETWORK_MGMT", "HANDSHAKE",
            "KEEPALIVE", "UNKNOWN",
        ]
        for name in expected:
            assert hasattr(TrafficCategory, name)


class TestTrafficClassification:
    """Tests for TrafficClassification dataclass."""

    def test_creation(self):
        """Test classification creation."""
        classification = TrafficClassification(
            category=TrafficCategory.WEB_BROWSING,
            confidence=0.9,
            subcategory="http",
            service="HTTP",
            is_encrypted=False,
            description="Web browsing",
        )
        assert classification.category == TrafficCategory.WEB_BROWSING
        assert classification.confidence == 0.9
        assert classification.is_encrypted is False


class TestTrafficClassifier:
    """Tests for TrafficClassifier class."""

    def test_creation(self, traffic_classifier):
        """Test classifier creation."""
        assert traffic_classifier is not None
        assert len(traffic_classifier.PORT_SERVICES) > 0

    def test_classify_https_port(self, traffic_classifier):
        """Test classification of HTTPS traffic (port 443)."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            packets_sent=10,
            packets_recv=10,
            bytes_sent=1000,
            bytes_recv=5000,
        )
        classification = traffic_classifier.classify_flow(flow)

        assert classification.category == TrafficCategory.ENCRYPTED
        assert classification.is_encrypted is True
        assert classification.service == "HTTPS"

    def test_classify_http_port(self, traffic_classifier):
        """Test classification of HTTP traffic (port 80)."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=80,
            protocol=6,
            protocol_name="TCP",
            packets_sent=10,
            packets_recv=10,
            bytes_sent=1000,
            bytes_recv=5000,
        )
        classification = traffic_classifier.classify_flow(flow)

        assert classification.category == TrafficCategory.WEB_BROWSING
        assert classification.service == "HTTP"

    def test_classify_dns_port(self, traffic_classifier):
        """Test classification of DNS traffic (port 53)."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
            protocol=17,
            protocol_name="UDP",
            packets_sent=1,
            packets_recv=1,
            bytes_sent=50,
            bytes_recv=200,
        )
        classification = traffic_classifier.classify_flow(flow)

        assert classification.category == TrafficCategory.DNS
        assert classification.service == "DNS"
        assert classification.confidence >= 0.9

    def test_classify_ssh_port(self, traffic_classifier):
        """Test classification of SSH traffic (port 22)."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=22,
            protocol=6,
            protocol_name="TCP",
            packets_sent=100,
            packets_recv=100,
            bytes_sent=5000,
            bytes_recv=5000,
        )
        classification = traffic_classifier.classify_flow(flow)

        assert classification.category == TrafficCategory.REMOTE_ACCESS
        assert classification.service == "SSH"

    def test_classify_email_ports(self, traffic_classifier):
        """Test classification of email ports."""
        email_ports = [25, 110, 143, 465, 587, 993, 995]
        for port in email_ports:
            flow = Flow(
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                src_port=54321,
                dst_port=port,
                protocol=6,
                protocol_name="TCP",
            )
            classification = traffic_classifier.classify_flow(flow)
            assert classification.category == TrafficCategory.EMAIL, f"Port {port} should be EMAIL"

    def test_classify_database_ports(self, traffic_classifier):
        """Test classification of database ports."""
        db_ports = {
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            27017: "MongoDB",
            6379: "Redis",
        }
        for port, expected_service in db_ports.items():
            flow = Flow(
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                src_port=54321,
                dst_port=port,
                protocol=6,
                protocol_name="TCP",
            )
            classification = traffic_classifier.classify_flow(flow)
            assert classification.category == TrafficCategory.DATABASE, f"Port {port} should be DATABASE"
            assert classification.service == expected_service

    def test_classify_vpn_ports(self, traffic_classifier):
        """Test classification of VPN ports."""
        vpn_ports = [500, 1194, 1701, 1723, 4500, 51820]
        for port in vpn_ports:
            flow = Flow(
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                src_port=54321,
                dst_port=port,
                protocol=17,
                protocol_name="UDP",
            )
            classification = traffic_classifier.classify_flow(flow)
            assert classification.category == TrafficCategory.VPN_TUNNEL, f"Port {port} should be VPN_TUNNEL"

    def test_classify_icmp(self, traffic_classifier):
        """Test classification of ICMP traffic."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=8,  # ICMP type
            dst_port=0,  # ICMP code
            protocol=1,
            protocol_name="ICMP",
            packets_sent=10,
            packets_recv=10,
        )
        classification = traffic_classifier.classify_flow(flow)

        assert classification.category == TrafficCategory.NETWORK_MGMT
        assert classification.service == "ICMP"

    def test_detect_handshake(self, traffic_classifier):
        """Test detection of handshake traffic."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=12345,  # Unknown port
            protocol=6,
            protocol_name="TCP",
            packets_sent=3,
            packets_recv=3,
            bytes_sent=200,
            bytes_recv=200,
        )
        classification = traffic_classifier.classify_flow(flow)

        assert classification.category == TrafficCategory.HANDSHAKE

    def test_detect_keepalive(self, traffic_classifier):
        """Test detection of keepalive traffic."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=12345,  # Unknown port
            protocol=6,
            protocol_name="TCP",
            packets_sent=50,
            packets_recv=50,
            bytes_sent=1000,  # Small packets
            bytes_recv=1000,
            first_seen=time.time() - 100,  # Long duration
            last_seen=time.time(),
        )
        classification = traffic_classifier.classify_flow(flow)

        assert classification.category == TrafficCategory.KEEPALIVE

    def test_detect_streaming(self, traffic_classifier):
        """Test detection of streaming traffic."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=12345,  # Unknown port
            protocol=6,
            protocol_name="TCP",
            packets_sent=10,
            packets_recv=500,
            bytes_sent=1000,
            bytes_recv=500000,  # High bytes, mostly receiving
        )
        classification = traffic_classifier.classify_flow(flow)

        assert classification.category == TrafficCategory.VIDEO_STREAMING

    def test_detect_voip(self, traffic_classifier):
        """Test detection of VoIP traffic patterns."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=12345,  # Unknown port
            protocol=17,
            protocol_name="UDP",
            packets_sent=100,
            packets_recv=100,
            bytes_sent=16000,  # ~160 bytes per packet
            bytes_recv=16000,
            first_seen=time.time() - 60,
            last_seen=time.time(),
        )
        classification = traffic_classifier.classify_flow(flow)

        assert classification.category == TrafficCategory.VOIP

    def test_classify_unknown_port(self, traffic_classifier):
        """Test classification of unknown port."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=9999,  # Uncommon port
            protocol=6,
            protocol_name="TCP",
            packets_sent=10,
            packets_recv=10,
            bytes_sent=10000,
            bytes_recv=10000,
        )
        classification = traffic_classifier.classify_flow(flow)

        # Should not crash, might be UNKNOWN or detected by pattern
        assert classification.category is not None

    def test_caching(self, traffic_classifier):
        """Test that classifications are cached."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
        )

        classification1 = traffic_classifier.classify_flow(flow)
        classification2 = traffic_classifier.get_classification(flow)

        assert classification1 == classification2

    def test_get_category_stats(self, traffic_classifier):
        """Test category statistics collection."""
        flows = [
            Flow(src_ip="192.168.1.1", dst_ip="8.8.8.8", src_port=54321, dst_port=443, protocol=6, protocol_name="TCP", bytes_sent=1000, bytes_recv=2000),
            Flow(src_ip="192.168.1.2", dst_ip="8.8.8.8", src_port=54322, dst_port=443, protocol=6, protocol_name="TCP", bytes_sent=1000, bytes_recv=2000),
            Flow(src_ip="192.168.1.3", dst_ip="8.8.8.8", src_port=54323, dst_port=53, protocol=17, protocol_name="UDP", bytes_sent=100, bytes_recv=200),
        ]

        for flow in flows:
            traffic_classifier.classify_flow(flow)

        stats = traffic_classifier.get_category_stats()

        assert TrafficCategory.ENCRYPTED in stats
        assert stats[TrafficCategory.ENCRYPTED][0] == 2  # count
        assert TrafficCategory.DNS in stats
        assert stats[TrafficCategory.DNS][0] == 1

    def test_get_category_name(self, traffic_classifier):
        """Test human-readable category names."""
        assert traffic_classifier.get_category_name(TrafficCategory.WEB_BROWSING) == "Web Browsing"
        assert traffic_classifier.get_category_name(TrafficCategory.DNS) == "DNS Lookup"
        assert traffic_classifier.get_category_name(TrafficCategory.VOIP) == "VoIP/Calling"

    def test_clear(self, traffic_classifier):
        """Test clearing classifier state."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
        )
        traffic_classifier.classify_flow(flow)

        traffic_classifier.clear()

        # Cache should be empty
        assert traffic_classifier.get_classification(flow) is None
        assert len(traffic_classifier.category_counts) == 0
