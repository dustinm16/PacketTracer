"""Shared fixtures for PacketTracer tests."""

import os
import sys
import time
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================================
# Packet Fixtures
# ============================================================================

@pytest.fixture
def mock_tcp_packet():
    """Create a mock TCP packet."""
    packet = MagicMock()
    packet.haslayer.side_effect = lambda layer: layer.__name__ in ['IP', 'TCP', 'Ether']

    # IP layer
    ip_layer = MagicMock()
    ip_layer.src = "192.168.1.100"
    ip_layer.dst = "8.8.8.8"
    ip_layer.proto = 6  # TCP
    ip_layer.ttl = 64
    packet.__getitem__ = lambda self, layer: {
        'IP': ip_layer,
        'TCP': MagicMock(sport=54321, dport=443, flags='S', seq=1000, ack=0),
        'Ether': MagicMock(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66'),
    }.get(layer.__name__, MagicMock())
    packet.time = time.time()
    packet.__len__ = lambda self: 64

    return packet


@pytest.fixture
def mock_udp_packet():
    """Create a mock UDP packet."""
    packet = MagicMock()
    packet.haslayer.side_effect = lambda layer: layer.__name__ in ['IP', 'UDP', 'Ether']

    ip_layer = MagicMock()
    ip_layer.src = "192.168.1.100"
    ip_layer.dst = "8.8.8.8"
    ip_layer.proto = 17  # UDP
    ip_layer.ttl = 64
    packet.__getitem__ = lambda self, layer: {
        'IP': ip_layer,
        'UDP': MagicMock(sport=54321, dport=53),
        'Ether': MagicMock(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66'),
    }.get(layer.__name__, MagicMock())
    packet.time = time.time()
    packet.__len__ = lambda self: 72

    return packet


@pytest.fixture
def mock_icmp_packet():
    """Create a mock ICMP packet."""
    packet = MagicMock()
    packet.haslayer.side_effect = lambda layer: layer.__name__ in ['IP', 'ICMP', 'Ether']

    ip_layer = MagicMock()
    ip_layer.src = "192.168.1.100"
    ip_layer.dst = "8.8.8.8"
    ip_layer.proto = 1  # ICMP
    ip_layer.ttl = 64
    packet.__getitem__ = lambda self, layer: {
        'IP': ip_layer,
        'ICMP': MagicMock(type=8, code=0),
        'Ether': MagicMock(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66'),
    }.get(layer.__name__, MagicMock())
    packet.time = time.time()
    packet.__len__ = lambda self: 84

    return packet


# ============================================================================
# ParsedPacket Fixtures
# ============================================================================

@pytest.fixture
def parsed_tcp_packet():
    """Create a ParsedPacket for TCP traffic."""
    from capture.parser import ParsedPacket
    return ParsedPacket(
        timestamp=time.time(),
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=443,
        protocol=6,
        protocol_name="TCP",
        ttl=64,
        length=1500,
        flags="S",
        seq=1000,
        ack=0,
    )


@pytest.fixture
def parsed_udp_packet():
    """Create a ParsedPacket for UDP/DNS traffic."""
    from capture.parser import ParsedPacket
    return ParsedPacket(
        timestamp=time.time(),
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        protocol=17,
        protocol_name="UDP",
        ttl=64,
        length=72,
        flags="",
    )


@pytest.fixture
def parsed_icmp_packet():
    """Create a ParsedPacket for ICMP traffic."""
    from capture.parser import ParsedPacket
    return ParsedPacket(
        timestamp=time.time(),
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=8,  # ICMP type
        dst_port=0,  # ICMP code
        protocol=1,
        protocol_name="ICMP",
        ttl=64,
        length=84,
        flags="",
        icmp_type=8,
        icmp_code=0,
    )


# ============================================================================
# Flow Fixtures
# ============================================================================

@pytest.fixture
def sample_flow():
    """Create a sample Flow object."""
    from tracking.flow import Flow
    return Flow(
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=443,
        protocol=6,
        protocol_name="TCP",
        packets_sent=100,
        packets_recv=150,
        bytes_sent=50000,
        bytes_recv=150000,
        first_seen=time.time() - 60,
        last_seen=time.time(),
    )


@pytest.fixture
def flow_tracker():
    """Create a FlowTracker instance."""
    from tracking.flow import FlowTracker
    return FlowTracker(max_flows=1000, timeout=300)


# ============================================================================
# Database Fixtures
# ============================================================================

@pytest.fixture
def temp_db_path():
    """Create a temporary database path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield os.path.join(tmpdir, "test.db")


@pytest.fixture
def connection_pool(temp_db_path):
    """Create a ConnectionPool with a temporary database."""
    from db.connection import ConnectionPool
    pool = ConnectionPool(db_path=temp_db_path, read_pool_size=2, wal_mode=True)
    pool.initialize()
    yield pool
    pool.close()


# ============================================================================
# Cache Fixtures
# ============================================================================

@pytest.fixture
def geo_cache():
    """Create a GeoCache instance."""
    from geo.cache import GeoCache
    return GeoCache(max_size=100, ttl=60)


# ============================================================================
# Classifier Fixtures
# ============================================================================

@pytest.fixture
def traffic_classifier():
    """Create a TrafficClassifier instance."""
    from tracking.classifier import TrafficClassifier
    return TrafficClassifier()


# ============================================================================
# Port Tracker Fixtures
# ============================================================================

@pytest.fixture
def port_tracker():
    """Create a PortTracker instance."""
    from tracking.ports import PortTracker
    return PortTracker(max_ports=100, scan_window=60)
