"""Tests for deep packet inspection module."""

import pytest
from analysis.dpi import (
    DeepPacketInspector,
    PacketCapture,
    FlowInspection,
    OSFingerprint,
    ApplicationSignature,
    OSFamily,
)


class TestOSFingerprint:
    """Tests for OS fingerprint."""

    def test_creation(self):
        fp = OSFingerprint()
        assert fp.os_family == OSFamily.UNKNOWN
        assert fp.confidence == 0.0

    def test_with_values(self):
        fp = OSFingerprint(
            os_family=OSFamily.LINUX,
            initial_ttl=64,
            confidence=0.8,
        )
        assert fp.os_family == OSFamily.LINUX
        assert fp.initial_ttl == 64
        assert fp.confidence == 0.8

    def test_reasoning(self):
        fp = OSFingerprint()
        fp.reasoning.append("TTL indicates Linux")
        assert len(fp.reasoning) == 1

    def test_to_dict(self):
        fp = OSFingerprint(
            os_family=OSFamily.WINDOWS,
            initial_ttl=128,
            confidence=0.7,
        )
        d = fp.to_dict()
        assert d["os_family"] == "Windows"
        assert d["initial_ttl"] == 128


class TestApplicationSignature:
    """Tests for application signatures."""

    def test_creation(self):
        sig = ApplicationSignature(protocol="HTTP", version="1.1")
        assert sig.protocol == "HTTP"
        assert sig.version == "1.1"

    def test_tls_signature(self):
        sig = ApplicationSignature(
            protocol="TLS",
            version="1.2",
            sni_hostname="example.com",
            confidence=0.95,
        )
        assert sig.sni_hostname == "example.com"
        assert sig.confidence == 0.95

    def test_http_signature(self):
        sig = ApplicationSignature(
            protocol="HTTP",
            http_method="GET",
            http_host="example.com",
            http_path="/api/v1",
            user_agent="Mozilla/5.0",
        )
        assert sig.http_method == "GET"
        assert sig.http_host == "example.com"


class TestPacketCapture:
    """Tests for packet capture."""

    def test_creation(self):
        cap = PacketCapture(
            timestamp=1234567890.0,
            direction="send",
            length=100,
            raw_bytes=b"\x00\x01\x02\x03",
        )
        assert cap.timestamp == 1234567890.0
        assert cap.direction == "send"
        assert cap.length == 100

    def test_hex_dump(self):
        cap = PacketCapture(
            timestamp=0,
            direction="send",
            length=4,
            raw_bytes=b"\x48\x65\x6c\x6c\x6f",  # "Hello"
        )
        dump = cap.hex_dump()
        assert "48 65 6c 6c 6f" in dump
        assert "Hello" in dump

    def test_hex_dump_non_printable(self):
        cap = PacketCapture(
            timestamp=0,
            direction="send",
            length=4,
            raw_bytes=b"\x00\x01\x02\x03",
        )
        dump = cap.hex_dump()
        assert "00 01 02 03" in dump
        assert "...." in dump

    def test_payload_hex_dump_empty(self):
        cap = PacketCapture(
            timestamp=0,
            direction="send",
            length=0,
            raw_bytes=b"",
            payload=b"",
        )
        dump = cap.payload_hex_dump()
        assert "no payload" in dump

    def test_payload_hex_dump(self):
        cap = PacketCapture(
            timestamp=0,
            direction="recv",
            length=20,
            raw_bytes=b"\x00" * 20,
            payload=b"HTTP/1.1 200 OK",
        )
        dump = cap.payload_hex_dump()
        assert "48 54 54 50" in dump  # HTTP


class TestFlowInspection:
    """Tests for flow inspection."""

    def test_creation(self):
        insp = FlowInspection(
            flow_key="test_key",
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
        )
        assert insp.flow_key == "test_key"
        assert insp.src_ip == "192.168.1.100"
        assert insp.total_packets == 0

    def test_with_fingerprints(self):
        insp = FlowInspection(
            flow_key="test",
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            src_fingerprint=OSFingerprint(os_family=OSFamily.LINUX),
        )
        assert insp.src_fingerprint.os_family == OSFamily.LINUX


class TestDeepPacketInspector:
    """Tests for DPI engine."""

    def test_creation(self):
        dpi = DeepPacketInspector()
        assert dpi.max_packets_per_flow == 100

    def test_add_target(self):
        dpi = DeepPacketInspector()
        dpi.add_target("flow1")
        assert dpi.is_target("flow1")
        assert not dpi.is_target("flow2")

    def test_remove_target(self):
        dpi = DeepPacketInspector()
        dpi.add_target("flow1")
        dpi.remove_target("flow1")
        assert not dpi.is_target("flow1")

    def test_clear_targets(self):
        dpi = DeepPacketInspector()
        dpi.add_target("flow1")
        dpi.add_target("flow2")
        dpi.clear_targets()
        assert len(dpi.get_targets()) == 0

    def test_get_inspection_empty(self):
        dpi = DeepPacketInspector()
        assert dpi.get_inspection("nonexistent") is None

    def test_get_stats(self):
        dpi = DeepPacketInspector()
        dpi.add_target("flow1")
        stats = dpi.get_stats()
        assert stats["active_targets"] == 1
        assert stats["inspections"] == 0

    def test_clear_all(self):
        dpi = DeepPacketInspector()
        dpi.clear_all()
        assert len(dpi.get_all_inspections()) == 0


class TestApplicationDetection:
    """Tests for application protocol detection."""

    def test_http_detection(self):
        dpi = DeepPacketInspector()
        app = dpi._detect_application(b"GET /index.html HTTP/1.1\r\n")
        assert app is not None
        assert app.protocol == "HTTP"

    def test_tls_detection(self):
        dpi = DeepPacketInspector()
        # TLS 1.2 Client Hello start
        payload = b"\x16\x03\x03\x00\x05test"
        app = dpi._detect_application(payload)
        assert app is not None
        assert app.protocol == "TLS"
        assert app.version == "1.2"

    def test_ssh_detection(self):
        dpi = DeepPacketInspector()
        app = dpi._detect_application(b"SSH-2.0-OpenSSH_8.9")
        assert app is not None
        assert app.protocol == "SSH"
        assert app.version == "2.0"

    def test_unknown_protocol(self):
        dpi = DeepPacketInspector()
        app = dpi._detect_application(b"\x00\x00\x00\x00random")
        assert app is None


class TestHexDumpFormatting:
    """Tests for hex dump output formatting."""

    def test_long_packet(self):
        data = bytes(range(256))
        cap = PacketCapture(
            timestamp=0,
            direction="send",
            length=256,
            raw_bytes=data,
        )
        dump = cap.hex_dump()
        lines = dump.split("\n")
        # Should have 16 lines (256 bytes / 16 bytes per line)
        assert len(lines) == 16

    def test_offset_format(self):
        cap = PacketCapture(
            timestamp=0,
            direction="send",
            length=32,
            raw_bytes=b"\x00" * 32,
        )
        dump = cap.hex_dump()
        assert "00000000" in dump
        assert "00000010" in dump
