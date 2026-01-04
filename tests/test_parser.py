"""Tests for capture/parser.py module."""

import time
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from capture.parser import (
    PacketParser,
    ParsedPacket,
    DNSInfo,
    DNSQueryInfo,
    DNSAnswerInfo,
    DNS_TYPES,
    DNS_RCODES,
)


class TestParsedPacket:
    """Tests for ParsedPacket dataclass."""

    def test_flow_key(self):
        """Test flow_key property returns 5-tuple."""
        packet = ParsedPacket(
            timestamp=time.time(),
            src_mac=None,
            dst_mac=None,
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            ttl=64,
            length=100,
            flags="S",
        )
        key = packet.flow_key
        assert key == ("192.168.1.1", "8.8.8.8", 54321, 443, 6)

    def test_reverse_flow_key(self):
        """Test reverse_flow_key property."""
        packet = ParsedPacket(
            timestamp=time.time(),
            src_mac=None,
            dst_mac=None,
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            ttl=64,
            length=100,
            flags="S",
        )
        key = packet.reverse_flow_key
        assert key == ("8.8.8.8", "192.168.1.1", 443, 54321, 6)

    def test_optional_fields(self):
        """Test optional fields default to None."""
        packet = ParsedPacket(
            timestamp=time.time(),
            src_mac=None,
            dst_mac=None,
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            src_port=0,
            dst_port=0,
            protocol=1,
            protocol_name="ICMP",
            ttl=64,
            length=84,
            flags="",
        )
        assert packet.seq is None
        assert packet.ack is None
        assert packet.icmp_type is None
        assert packet.icmp_code is None
        assert packet.dns is None


class TestDNSInfo:
    """Tests for DNS information dataclasses."""

    def test_dns_query_info(self):
        """Test DNSQueryInfo creation."""
        query = DNSQueryInfo(
            name="example.com",
            qtype=1,
            qtype_name="A",
            qclass=1,
        )
        assert query.name == "example.com"
        assert query.qtype == 1
        assert query.qtype_name == "A"

    def test_dns_answer_info(self):
        """Test DNSAnswerInfo creation."""
        answer = DNSAnswerInfo(
            name="example.com",
            rtype=1,
            rtype_name="A",
            rdata="93.184.216.34",
            ttl=3600,
        )
        assert answer.name == "example.com"
        assert answer.rdata == "93.184.216.34"
        assert answer.ttl == 3600

    def test_dns_info_query_names(self):
        """Test DNSInfo.query_names property."""
        dns_info = DNSInfo(
            transaction_id=12345,
            is_response=False,
            is_query=True,
            opcode=0,
            rcode=0,
            rcode_name="NOERROR",
            queries=[
                DNSQueryInfo(name="example.com", qtype=1, qtype_name="A"),
                DNSQueryInfo(name="example.org", qtype=28, qtype_name="AAAA"),
            ],
        )
        assert dns_info.query_names == ["example.com", "example.org"]

    def test_dns_info_answer_ips(self):
        """Test DNSInfo.answer_ips property."""
        dns_info = DNSInfo(
            transaction_id=12345,
            is_response=True,
            is_query=False,
            opcode=0,
            rcode=0,
            rcode_name="NOERROR",
            answers=[
                DNSAnswerInfo(name="example.com", rtype=1, rtype_name="A", rdata="93.184.216.34"),
                DNSAnswerInfo(name="example.com", rtype=28, rtype_name="AAAA", rdata="2606:2800:220:1:248:1893:25c8:1946"),
                DNSAnswerInfo(name="example.com", rtype=5, rtype_name="CNAME", rdata="www.example.com"),
            ],
        )
        ips = dns_info.answer_ips
        assert "93.184.216.34" in ips
        assert "2606:2800:220:1:248:1893:25c8:1946" in ips
        assert "www.example.com" not in ips  # CNAME should not be included


class TestDNSConstants:
    """Tests for DNS constant definitions."""

    def test_dns_types(self):
        """Test common DNS types are defined."""
        assert DNS_TYPES[1] == "A"
        assert DNS_TYPES[28] == "AAAA"
        assert DNS_TYPES[5] == "CNAME"
        assert DNS_TYPES[15] == "MX"
        assert DNS_TYPES[2] == "NS"
        assert DNS_TYPES[6] == "SOA"

    def test_dns_rcodes(self):
        """Test DNS response codes are defined."""
        assert DNS_RCODES[0] == "NOERROR"
        assert DNS_RCODES[3] == "NXDOMAIN"
        assert DNS_RCODES[2] == "SERVFAIL"
        assert DNS_RCODES[5] == "REFUSED"


class TestPacketParser:
    """Tests for PacketParser class."""

    def test_parse_returns_none_for_non_ip(self):
        """Test that non-IP packets return None."""
        packet = MagicMock()
        packet.haslayer.return_value = False

        result = PacketParser.parse(packet)
        assert result is None

    def test_parse_tcp_packet(self):
        """Test parsing a TCP packet."""
        # Create mock layers
        packet = MagicMock()

        # Configure haslayer
        def has_layer(layer):
            return layer.__name__ in ['IP', 'TCP', 'Ether']
        packet.haslayer.side_effect = has_layer

        # Create mock IP layer
        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.100"
        ip_mock.dst = "8.8.8.8"
        ip_mock.proto = 6
        ip_mock.ttl = 64

        # Create mock TCP layer
        tcp_mock = MagicMock()
        tcp_mock.sport = 54321
        tcp_mock.dport = 443
        tcp_mock.flags = MagicMock()
        tcp_mock.flags.__str__ = lambda self: "S"
        tcp_mock.seq = 1000
        tcp_mock.ack = 0

        # Create mock Ethernet layer
        ether_mock = MagicMock()
        ether_mock.src = "aa:bb:cc:dd:ee:ff"
        ether_mock.dst = "11:22:33:44:55:66"

        # Configure getitem
        def get_layer(layer):
            if layer.__name__ == 'IP':
                return ip_mock
            elif layer.__name__ == 'TCP':
                return tcp_mock
            elif layer.__name__ == 'Ether':
                return ether_mock
            return MagicMock()
        packet.__getitem__.side_effect = get_layer

        packet.time = time.time()
        packet.__len__ = MagicMock(return_value=64)

        result = PacketParser.parse(packet)

        assert result is not None
        assert result.src_ip == "192.168.1.100"
        assert result.dst_ip == "8.8.8.8"
        assert result.src_port == 54321
        assert result.dst_port == 443
        assert result.protocol == 6
        assert result.ttl == 64

    def test_parse_udp_packet(self):
        """Test parsing a UDP packet."""
        packet = MagicMock()

        def has_layer(layer):
            return layer.__name__ in ['IP', 'UDP']
        packet.haslayer.side_effect = has_layer

        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.100"
        ip_mock.dst = "8.8.8.8"
        ip_mock.proto = 17
        ip_mock.ttl = 64

        udp_mock = MagicMock()
        udp_mock.sport = 54321
        udp_mock.dport = 53

        def get_layer(layer):
            if layer.__name__ == 'IP':
                return ip_mock
            elif layer.__name__ == 'UDP':
                return udp_mock
            return MagicMock()
        packet.__getitem__.side_effect = get_layer

        packet.time = time.time()
        packet.__len__ = MagicMock(return_value=72)

        result = PacketParser.parse(packet)

        assert result is not None
        assert result.src_port == 54321
        assert result.dst_port == 53
        assert result.protocol == 17
        assert result.protocol_name == "UDP"

    def test_parse_icmp_packet(self):
        """Test parsing an ICMP packet."""
        packet = MagicMock()

        def has_layer(layer):
            return layer.__name__ in ['IP', 'ICMP']
        packet.haslayer.side_effect = has_layer

        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.100"
        ip_mock.dst = "8.8.8.8"
        ip_mock.proto = 1
        ip_mock.ttl = 64

        icmp_mock = MagicMock()
        icmp_mock.type = 8  # Echo request
        icmp_mock.code = 0

        def get_layer(layer):
            if layer.__name__ == 'IP':
                return ip_mock
            elif layer.__name__ == 'ICMP':
                return icmp_mock
            return MagicMock()
        packet.__getitem__.side_effect = get_layer

        packet.time = time.time()
        packet.__len__ = MagicMock(return_value=84)

        result = PacketParser.parse(packet)

        assert result is not None
        assert result.protocol == 1
        assert result.protocol_name == "ICMP"
        assert result.icmp_type == 8
        assert result.icmp_code == 0
        # ICMP type/code used as pseudo-ports
        assert result.src_port == 8
        assert result.dst_port == 0
