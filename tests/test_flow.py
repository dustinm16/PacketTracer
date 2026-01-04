"""Tests for tracking/flow.py module."""

import time
import pytest
from tracking.flow import Flow, FlowTracker, FlowKey


class TestFlow:
    """Tests for Flow dataclass."""

    def test_flow_creation(self, sample_flow):
        """Test basic flow creation."""
        assert sample_flow.src_ip == "192.168.1.100"
        assert sample_flow.dst_ip == "8.8.8.8"
        assert sample_flow.protocol == 6
        assert sample_flow.protocol_name == "TCP"

    def test_flow_key_property(self, sample_flow):
        """Test flow_key property format."""
        key = sample_flow.flow_key
        assert key == "192.168.1.100:54321-8.8.8.8:443-6"

    def test_total_packets(self, sample_flow):
        """Test total_packets property."""
        assert sample_flow.total_packets == 250  # 100 + 150

    def test_total_bytes(self, sample_flow):
        """Test total_bytes property."""
        assert sample_flow.total_bytes == 200000  # 50000 + 150000

    def test_duration(self, sample_flow):
        """Test duration property."""
        duration = sample_flow.duration
        assert duration >= 0
        assert duration <= 61  # Should be around 60 seconds

    def test_estimated_hops_linux(self):
        """Test hop estimation for Linux (TTL 64)."""
        flow = Flow(
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            ttl_values=[60, 59, 58],
        )
        flow.min_ttl = 58
        hops = flow.estimated_hops
        assert hops == 6  # 64 - 58

    def test_estimated_hops_windows(self):
        """Test hop estimation for Windows (TTL 128)."""
        flow = Flow(
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            ttl_values=[120, 119, 118],
        )
        flow.min_ttl = 118
        hops = flow.estimated_hops
        assert hops == 10  # 128 - 118

    def test_estimated_hops_network_device(self):
        """Test hop estimation for network devices (TTL 255)."""
        flow = Flow(
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            ttl_values=[250, 249],
        )
        flow.min_ttl = 249
        hops = flow.estimated_hops
        assert hops == 6  # 255 - 249

    def test_estimated_hops_no_ttl_values(self):
        """Test hop estimation with no TTL values."""
        flow = Flow(
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
        )
        assert flow.estimated_hops is None

    def test_update_from_packet_outbound(self, parsed_tcp_packet):
        """Test update_from_packet for outbound traffic."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
        )
        initial_bytes_sent = flow.bytes_sent
        initial_packets_sent = flow.packets_sent

        flow.update_from_packet(parsed_tcp_packet, is_outbound=True)

        assert flow.packets_sent == initial_packets_sent + 1
        assert flow.bytes_sent == initial_bytes_sent + parsed_tcp_packet.length

    def test_update_from_packet_inbound(self, parsed_tcp_packet):
        """Test update_from_packet for inbound traffic."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
        )
        initial_bytes_recv = flow.bytes_recv
        initial_packets_recv = flow.packets_recv

        flow.update_from_packet(parsed_tcp_packet, is_outbound=False)

        assert flow.packets_recv == initial_packets_recv + 1
        assert flow.bytes_recv == initial_bytes_recv + parsed_tcp_packet.length

    def test_update_tracks_ttl(self, parsed_tcp_packet):
        """Test that update_from_packet tracks TTL values."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
        )
        flow.update_from_packet(parsed_tcp_packet, is_outbound=True)

        assert 64 in flow.ttl_values
        assert flow.min_ttl == 64
        assert flow.max_ttl == 64

    def test_ttl_list_truncation(self, parsed_tcp_packet):
        """Test that TTL list is truncated to 100 values."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
        )
        # Add 110 packets
        for _ in range(110):
            flow.update_from_packet(parsed_tcp_packet, is_outbound=True)

        assert len(flow.ttl_values) == 100

    def test_is_expired(self):
        """Test is_expired method."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            last_seen=time.time() - 400,  # 400 seconds ago
        )
        assert flow.is_expired(timeout=300) is True
        assert flow.is_expired(timeout=500) is False


class TestFlowTracker:
    """Tests for FlowTracker class."""

    def test_creation(self, flow_tracker):
        """Test FlowTracker creation."""
        assert flow_tracker.max_flows == 1000
        assert flow_tracker.timeout == 300
        assert flow_tracker.flow_count == 0

    def test_process_packet_creates_flow(self, flow_tracker, parsed_tcp_packet):
        """Test that processing a packet creates a new flow."""
        flow = flow_tracker.process_packet(parsed_tcp_packet)

        assert flow is not None
        assert flow_tracker.flow_count == 1
        assert flow.total_packets == 1

    def test_process_packet_updates_existing_flow(self, flow_tracker, parsed_tcp_packet):
        """Test that processing packets updates existing flow."""
        flow1 = flow_tracker.process_packet(parsed_tcp_packet)
        flow2 = flow_tracker.process_packet(parsed_tcp_packet)

        assert flow1.flow_key == flow2.flow_key
        assert flow_tracker.flow_count == 1
        assert flow2.total_packets == 2

    def test_bidirectional_flow_key_normalization(self, flow_tracker):
        """Test that bidirectional traffic uses same flow key."""
        from capture.parser import ParsedPacket

        # Outbound packet
        outbound = ParsedPacket(
            timestamp=time.time(),
            src_mac=None,
            dst_mac=None,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            ttl=64,
            length=100,
            flags="S",
        )

        # Inbound packet (reversed)
        inbound = ParsedPacket(
            timestamp=time.time(),
            src_mac=None,
            dst_mac=None,
            src_ip="8.8.8.8",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol=6,
            protocol_name="TCP",
            ttl=56,
            length=100,
            flags="SA",
        )

        flow_tracker.process_packet(outbound)
        flow_tracker.process_packet(inbound)

        # Should be same flow
        assert flow_tracker.flow_count == 1

        flows = flow_tracker.get_flows()
        assert len(flows) == 1
        assert flows[0].packets_sent == 1
        assert flows[0].packets_recv == 1

    def test_get_flows(self, flow_tracker, parsed_tcp_packet, parsed_udp_packet):
        """Test get_flows returns all flows."""
        flow_tracker.process_packet(parsed_tcp_packet)
        flow_tracker.process_packet(parsed_udp_packet)

        flows = flow_tracker.get_flows()
        assert len(flows) == 2

    def test_get_flow_by_key(self, flow_tracker, parsed_tcp_packet):
        """Test getting specific flow by key."""
        flow_tracker.process_packet(parsed_tcp_packet)

        key = parsed_tcp_packet.flow_key
        flow = flow_tracker.get_flow(key)

        assert flow is not None
        assert flow.src_ip == parsed_tcp_packet.src_ip

    def test_get_top_flows_by_bytes(self, flow_tracker):
        """Test get_top_flows sorts by bytes correctly."""
        from capture.parser import ParsedPacket

        # Create flows with different byte counts
        for i, length in enumerate([100, 500, 200]):
            packet = ParsedPacket(
                timestamp=time.time(),
                src_mac=None,
                dst_mac=None,
                src_ip="192.168.1.100",
                dst_ip=f"8.8.8.{i}",
                src_port=54321,
                dst_port=443,
                protocol=6,
                protocol_name="TCP",
                ttl=64,
                length=length,
                flags="S",
            )
            flow_tracker.process_packet(packet)

        top_flows = flow_tracker.get_top_flows(n=3, by="bytes")
        assert len(top_flows) == 3
        assert top_flows[0].total_bytes >= top_flows[1].total_bytes
        assert top_flows[1].total_bytes >= top_flows[2].total_bytes

    def test_get_active_flows(self, flow_tracker, parsed_tcp_packet):
        """Test get_active_flows filters by timeout."""
        flow_tracker.process_packet(parsed_tcp_packet)

        active = flow_tracker.get_active_flows(timeout=60)
        assert len(active) == 1

        # With very short timeout, flow should not be active
        time.sleep(0.1)
        active = flow_tracker.get_active_flows(timeout=0.05)
        assert len(active) == 0

    def test_cleanup_expired(self, flow_tracker):
        """Test cleanup_expired removes old flows."""
        from capture.parser import ParsedPacket

        old_packet = ParsedPacket(
            timestamp=time.time() - 400,  # 400 seconds ago
            src_mac=None,
            dst_mac=None,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            ttl=64,
            length=100,
            flags="S",
        )
        flow_tracker.process_packet(old_packet)
        assert flow_tracker.flow_count == 1

        removed = flow_tracker.cleanup_expired()
        assert removed == 1
        assert flow_tracker.flow_count == 0

    def test_max_flows_pruning(self):
        """Test that flows are pruned when exceeding max."""
        from tracking.flow import FlowTracker
        from capture.parser import ParsedPacket

        tracker = FlowTracker(max_flows=10, timeout=300)

        # Add 15 flows
        for i in range(15):
            packet = ParsedPacket(
                timestamp=time.time(),
                src_mac=None,
                dst_mac=None,
                src_ip="192.168.1.100",
                dst_ip=f"8.8.8.{i}",
                src_port=54321,
                dst_port=443,
                protocol=6,
                protocol_name="TCP",
                ttl=64,
                length=100,
                flags="S",
            )
            tracker.process_packet(packet)

        # Should have pruned to stay at or below max
        assert tracker.flow_count <= 10

    def test_statistics_tracking(self, flow_tracker, parsed_tcp_packet):
        """Test that global statistics are tracked."""
        flow_tracker.process_packet(parsed_tcp_packet)
        flow_tracker.process_packet(parsed_tcp_packet)

        assert flow_tracker.total_packets == 2
        assert flow_tracker.total_bytes == parsed_tcp_packet.length * 2
