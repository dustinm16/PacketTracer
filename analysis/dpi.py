"""Deep Packet Inspection module for detailed flow analysis."""

import re
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import deque
from datetime import datetime
from enum import Enum

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether


class OSFamily(Enum):
    """Operating system families."""
    UNKNOWN = "Unknown"
    LINUX = "Linux"
    WINDOWS = "Windows"
    MACOS = "macOS"
    BSD = "BSD"
    IOS = "iOS"
    ANDROID = "Android"
    CISCO = "Cisco IOS"
    SOLARIS = "Solaris"
    EMBEDDED = "Embedded"


@dataclass
class OSFingerprint:
    """OS fingerprint based on packet characteristics."""
    os_family: OSFamily = OSFamily.UNKNOWN
    os_version: str = ""
    confidence: float = 0.0

    # Raw fingerprint data
    initial_ttl: int = 0
    tcp_window_size: int = 0
    tcp_options: List[str] = field(default_factory=list)
    tcp_mss: int = 0
    df_flag: bool = False  # Don't Fragment

    # Deduction reasoning
    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "os_family": self.os_family.value,
            "os_version": self.os_version,
            "confidence": self.confidence,
            "initial_ttl": self.initial_ttl,
            "tcp_window_size": self.tcp_window_size,
            "tcp_mss": self.tcp_mss,
            "df_flag": self.df_flag,
            "reasoning": self.reasoning,
        }


@dataclass
class ApplicationSignature:
    """Detected application/protocol signature."""
    protocol: str  # HTTP, TLS, SSH, DNS, etc.
    version: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0

    # For TLS
    sni_hostname: str = ""
    tls_version: str = ""
    cipher_suites: List[str] = field(default_factory=list)

    # For HTTP
    http_method: str = ""
    http_host: str = ""
    http_path: str = ""
    user_agent: str = ""
    server: str = ""
    content_type: str = ""

    # For SSH
    ssh_version: str = ""
    ssh_software: str = ""


@dataclass
class PacketCapture:
    """Captured packet with raw data."""
    timestamp: float
    direction: str  # "send" or "recv"
    length: int
    raw_bytes: bytes

    # Parsed info
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    flags: str = ""
    seq: int = 0
    ack: int = 0
    ttl: int = 0

    # Payload
    payload: bytes = b""
    payload_ascii: str = ""

    def hex_dump(self, bytes_per_line: int = 16) -> str:
        """Generate hex dump of packet."""
        lines = []
        data = self.raw_bytes

        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            # Pad hex part to fixed width
            hex_part = hex_part.ljust(bytes_per_line * 3 - 1)

            # ASCII representation
            ascii_part = "".join(
                chr(b) if 32 <= b < 127 else "."
                for b in chunk
            )

            lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")

        return "\n".join(lines)

    def payload_hex_dump(self, bytes_per_line: int = 16) -> str:
        """Generate hex dump of payload only."""
        if not self.payload:
            return "(no payload)"

        lines = []
        for i in range(0, len(self.payload), bytes_per_line):
            chunk = self.payload[i:i + bytes_per_line]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
            ascii_part = "".join(
                chr(b) if 32 <= b < 127 else "."
                for b in chunk
            )
            lines.append(f"{i:08x}  {hex_part}  |{ascii_part}|")

        return "\n".join(lines)


@dataclass
class FlowInspection:
    """Complete inspection results for a flow."""
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    # Fingerprinting
    src_fingerprint: Optional[OSFingerprint] = None
    dst_fingerprint: Optional[OSFingerprint] = None

    # Application detection
    application: Optional[ApplicationSignature] = None

    # Captured packets
    packets: List[PacketCapture] = field(default_factory=list)

    # Statistics
    total_bytes: int = 0
    total_packets: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0

    # Timing
    first_seen: float = 0
    last_seen: float = 0
    duration: float = 0

    # Analysis flags
    is_encrypted: bool = False
    has_payload: bool = False
    payload_entropy: float = 0.0

    # Deductive reasoning summary
    analysis_notes: List[str] = field(default_factory=list)


# Known TTL values for OS detection
TTL_SIGNATURES = {
    64: [OSFamily.LINUX, OSFamily.MACOS, OSFamily.ANDROID, OSFamily.IOS],
    128: [OSFamily.WINDOWS],
    255: [OSFamily.CISCO, OSFamily.SOLARIS],
    60: [OSFamily.EMBEDDED],
    32: [OSFamily.WINDOWS],  # Old Windows
}

# TCP window size hints
WINDOW_SIGNATURES = {
    (65535, OSFamily.MACOS): 0.7,
    (65535, OSFamily.LINUX): 0.3,
    (8192, OSFamily.WINDOWS): 0.6,
    (16384, OSFamily.WINDOWS): 0.7,
    (29200, OSFamily.LINUX): 0.8,
    (5840, OSFamily.LINUX): 0.7,
    (14600, OSFamily.LINUX): 0.6,
}

# Application layer signatures
APP_SIGNATURES = {
    # HTTP
    b"HTTP/1.": ("HTTP", "1.x"),
    b"HTTP/2": ("HTTP", "2"),
    b"GET ": ("HTTP", "request"),
    b"POST ": ("HTTP", "request"),
    b"PUT ": ("HTTP", "request"),
    b"DELETE ": ("HTTP", "request"),
    b"HEAD ": ("HTTP", "request"),
    b"OPTIONS ": ("HTTP", "request"),

    # TLS/SSL
    b"\x16\x03\x00": ("TLS", "SSLv3"),
    b"\x16\x03\x01": ("TLS", "1.0"),
    b"\x16\x03\x02": ("TLS", "1.1"),
    b"\x16\x03\x03": ("TLS", "1.2"),
    b"\x16\x03\x04": ("TLS", "1.3"),

    # SSH
    b"SSH-1.": ("SSH", "1.x"),
    b"SSH-2.0": ("SSH", "2.0"),

    # SMTP
    b"220 ": ("SMTP", "banner"),
    b"EHLO ": ("SMTP", "client"),
    b"HELO ": ("SMTP", "client"),

    # FTP
    b"220-": ("FTP", "banner"),
    b"USER ": ("FTP", "auth"),

    # DNS (already handled elsewhere, but for completeness)
    # MySQL
    b"\x00\x00\x00\x0a": ("MySQL", "handshake"),

    # PostgreSQL
    b"\x00\x00\x00\x08\x04\xd2\x16\x2f": ("PostgreSQL", "startup"),

    # Redis
    b"*": ("Redis", "command"),
    b"+OK": ("Redis", "response"),
    b"-ERR": ("Redis", "error"),

    # MQTT
    b"\x10": ("MQTT", "connect"),
    b"\x20": ("MQTT", "connack"),
}


class DeepPacketInspector:
    """Deep packet inspection engine."""

    def __init__(self, max_packets_per_flow: int = 100, max_payload_size: int = 65535):
        self.max_packets_per_flow = max_packets_per_flow
        self.max_payload_size = max_payload_size

        # Flow tracking
        self._inspections: Dict[str, FlowInspection] = {}
        self._lock = threading.Lock()

        # Active inspection targets (flow keys)
        self._targets: Set[str] = set()

    def add_target(self, flow_key: str) -> None:
        """Add a flow to inspection targets."""
        with self._lock:
            self._targets.add(flow_key)

    def remove_target(self, flow_key: str) -> None:
        """Remove a flow from inspection targets."""
        with self._lock:
            self._targets.discard(flow_key)

    def clear_targets(self) -> None:
        """Clear all inspection targets."""
        with self._lock:
            self._targets.clear()

    def is_target(self, flow_key: str) -> bool:
        """Check if flow is a target."""
        with self._lock:
            return flow_key in self._targets

    def get_targets(self) -> Set[str]:
        """Get current inspection targets."""
        with self._lock:
            return self._targets.copy()

    def process_packet(self, packet: Packet, flow_key: str) -> Optional[FlowInspection]:
        """Process a packet for deep inspection."""
        if not self.is_target(flow_key):
            return None

        with self._lock:
            if flow_key not in self._inspections:
                self._inspections[flow_key] = self._create_inspection(packet, flow_key)

            inspection = self._inspections[flow_key]
            capture = self._capture_packet(packet, inspection)

            if capture and len(inspection.packets) < self.max_packets_per_flow:
                inspection.packets.append(capture)
                self._update_inspection(inspection, capture)

            return inspection

    def _create_inspection(self, packet: Packet, flow_key: str) -> FlowInspection:
        """Create a new flow inspection."""
        ip_layer = packet[IP] if packet.haslayer(IP) else None

        src_ip = ip_layer.src if ip_layer else ""
        dst_ip = ip_layer.dst if ip_layer else ""
        src_port = 0
        dst_port = 0
        protocol = ""

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            protocol = "TCP"
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            protocol = "UDP"

        return FlowInspection(
            flow_key=flow_key,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            first_seen=float(packet.time),
            last_seen=float(packet.time),
        )

    def _capture_packet(self, packet: Packet, inspection: FlowInspection) -> Optional[PacketCapture]:
        """Capture packet data."""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        raw_bytes = bytes(packet)

        # Determine direction
        if ip_layer.src == inspection.src_ip:
            direction = "send"
        else:
            direction = "recv"

        # Extract transport layer info
        src_port = 0
        dst_port = 0
        flags = ""
        seq = 0
        ack = 0
        payload = b""

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = str(tcp.flags)
            seq = tcp.seq
            ack = tcp.ack
            if tcp.payload:
                payload = bytes(tcp.payload)[:self.max_payload_size]
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            if udp.payload:
                payload = bytes(udp.payload)[:self.max_payload_size]

        # Create ASCII representation of payload
        payload_ascii = ""
        if payload:
            payload_ascii = "".join(
                chr(b) if 32 <= b < 127 else "."
                for b in payload
            )

        return PacketCapture(
            timestamp=float(packet.time),
            direction=direction,
            length=len(packet),
            raw_bytes=raw_bytes,
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=inspection.protocol,
            flags=flags,
            seq=seq,
            ack=ack,
            ttl=ip_layer.ttl,
            payload=payload,
            payload_ascii=payload_ascii,
        )

    def _update_inspection(self, inspection: FlowInspection, capture: PacketCapture) -> None:
        """Update inspection with new capture."""
        inspection.last_seen = capture.timestamp
        inspection.duration = inspection.last_seen - inspection.first_seen
        inspection.total_packets += 1
        inspection.total_bytes += capture.length

        if capture.direction == "send":
            inspection.packets_sent += 1
            inspection.bytes_sent += capture.length
        else:
            inspection.packets_recv += 1
            inspection.bytes_recv += capture.length

        if capture.payload:
            inspection.has_payload = True

        # Update fingerprints on SYN packets
        if "S" in capture.flags and "A" not in capture.flags:
            fp = self._fingerprint_from_capture(capture)
            if capture.direction == "send":
                inspection.src_fingerprint = fp
            else:
                inspection.dst_fingerprint = fp

        # Detect application
        if capture.payload and not inspection.application:
            app = self._detect_application(capture.payload)
            if app:
                inspection.application = app
                self._extract_app_details(inspection, capture)

    def _fingerprint_from_capture(self, capture: PacketCapture) -> OSFingerprint:
        """Create OS fingerprint from packet capture."""
        fp = OSFingerprint()

        # Deduce initial TTL
        ttl = capture.ttl
        if ttl <= 32:
            fp.initial_ttl = 32
        elif ttl <= 60:
            fp.initial_ttl = 64
        elif ttl <= 64:
            fp.initial_ttl = 64
        elif ttl <= 128:
            fp.initial_ttl = 128
        else:
            fp.initial_ttl = 255

        fp.reasoning.append(f"Observed TTL={ttl}, estimated initial TTL={fp.initial_ttl}")

        # Determine OS family from TTL
        possible_os = TTL_SIGNATURES.get(fp.initial_ttl, [OSFamily.UNKNOWN])
        fp.os_family = possible_os[0] if possible_os else OSFamily.UNKNOWN
        fp.confidence = 0.5

        fp.reasoning.append(f"TTL {fp.initial_ttl} suggests {fp.os_family.value}")

        return fp

    def _detect_application(self, payload: bytes) -> Optional[ApplicationSignature]:
        """Detect application protocol from payload."""
        if not payload:
            return None

        for sig, (proto, version) in APP_SIGNATURES.items():
            if payload.startswith(sig):
                return ApplicationSignature(
                    protocol=proto,
                    version=version,
                    confidence=0.9,
                )

        # Check for TLS Client Hello
        if len(payload) > 5 and payload[0] == 0x16:
            if payload[1:3] in [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]:
                version_map = {
                    b"\x03\x01": "1.0",
                    b"\x03\x02": "1.1",
                    b"\x03\x03": "1.2",
                    b"\x03\x04": "1.3",
                }
                app = ApplicationSignature(
                    protocol="TLS",
                    version=version_map.get(payload[1:3], "unknown"),
                    confidence=0.95,
                )
                # Try to extract SNI
                sni = self._extract_tls_sni(payload)
                if sni:
                    app.sni_hostname = sni
                return app

        return None

    def _extract_tls_sni(self, payload: bytes) -> str:
        """Extract SNI hostname from TLS Client Hello."""
        try:
            # Very simplified SNI extraction
            # Look for SNI extension (type 0x00 0x00)
            if len(payload) < 50:
                return ""

            # Find SNI pattern - this is a simplified approach
            sni_marker = b"\x00\x00"  # SNI extension type
            idx = payload.find(sni_marker, 40)
            if idx == -1:
                return ""

            # Try to extract hostname
            # SNI format: type(2) + length(2) + list_length(2) + name_type(1) + name_length(2) + name
            if idx + 9 < len(payload):
                name_len_pos = idx + 7
                if name_len_pos + 2 < len(payload):
                    name_len = (payload[name_len_pos] << 8) | payload[name_len_pos + 1]
                    name_start = name_len_pos + 2
                    if name_start + name_len <= len(payload) and name_len < 256:
                        hostname = payload[name_start:name_start + name_len]
                        try:
                            return hostname.decode('ascii')
                        except:
                            pass
            return ""
        except:
            return ""

    def _extract_app_details(self, inspection: FlowInspection, capture: PacketCapture) -> None:
        """Extract detailed application information."""
        if not inspection.application:
            return

        payload = capture.payload
        proto = inspection.application.protocol

        if proto == "HTTP":
            self._extract_http_details(inspection.application, payload)
        elif proto == "SSH":
            self._extract_ssh_details(inspection.application, payload)

    def _extract_http_details(self, app: ApplicationSignature, payload: bytes) -> None:
        """Extract HTTP request/response details."""
        try:
            text = payload.decode('utf-8', errors='replace')
            lines = text.split('\r\n')

            if lines:
                first_line = lines[0]
                # Request
                if first_line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                    parts = first_line.split(' ')
                    if len(parts) >= 2:
                        app.http_method = parts[0]
                        app.http_path = parts[1]

                # Response
                elif first_line.startswith('HTTP/'):
                    app.version = first_line.split(' ')[0]

                # Headers
                for line in lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        key_lower = key.lower()
                        if key_lower == 'host':
                            app.http_host = value
                        elif key_lower == 'user-agent':
                            app.user_agent = value
                        elif key_lower == 'server':
                            app.server = value
                        elif key_lower == 'content-type':
                            app.content_type = value
        except:
            pass

    def _extract_ssh_details(self, app: ApplicationSignature, payload: bytes) -> None:
        """Extract SSH version details."""
        try:
            text = payload.decode('utf-8', errors='replace')
            if text.startswith('SSH-'):
                parts = text.strip().split(' ', 1)
                app.ssh_version = parts[0]
                if len(parts) > 1:
                    app.ssh_software = parts[1]
        except:
            pass

    def get_inspection(self, flow_key: str) -> Optional[FlowInspection]:
        """Get inspection for a flow."""
        with self._lock:
            return self._inspections.get(flow_key)

    def get_all_inspections(self) -> Dict[str, FlowInspection]:
        """Get all inspections."""
        with self._lock:
            return dict(self._inspections)

    def clear_inspection(self, flow_key: str) -> None:
        """Clear inspection for a flow."""
        with self._lock:
            self._inspections.pop(flow_key, None)

    def clear_all(self) -> None:
        """Clear all inspections."""
        with self._lock:
            self._inspections.clear()

    def analyze_flow(self, flow_key: str) -> Optional[FlowInspection]:
        """Perform comprehensive analysis on a flow."""
        with self._lock:
            inspection = self._inspections.get(flow_key)
            if not inspection:
                return None

            # Add analysis notes
            self._generate_analysis_notes(inspection)

            return inspection

    def _generate_analysis_notes(self, inspection: FlowInspection) -> None:
        """Generate deductive analysis notes for the inspection."""
        notes = []

        # OS fingerprint analysis
        if inspection.src_fingerprint:
            fp = inspection.src_fingerprint
            notes.append(f"Source appears to be {fp.os_family.value} (confidence: {fp.confidence:.0%})")
            notes.extend(fp.reasoning)

        if inspection.dst_fingerprint:
            fp = inspection.dst_fingerprint
            notes.append(f"Destination appears to be {fp.os_family.value} (confidence: {fp.confidence:.0%})")

        # Application analysis
        if inspection.application:
            app = inspection.application
            notes.append(f"Detected protocol: {app.protocol} {app.version}")

            if app.sni_hostname:
                notes.append(f"TLS SNI hostname: {app.sni_hostname}")
            if app.http_host:
                notes.append(f"HTTP Host: {app.http_host}")
            if app.user_agent:
                notes.append(f"User-Agent: {app.user_agent[:80]}")
            if app.ssh_software:
                notes.append(f"SSH Software: {app.ssh_software}")

        # Traffic pattern analysis
        if inspection.total_packets > 0:
            avg_size = inspection.total_bytes / inspection.total_packets
            notes.append(f"Average packet size: {avg_size:.0f} bytes")

            if inspection.duration > 0:
                pps = inspection.total_packets / inspection.duration
                bps = inspection.total_bytes / inspection.duration
                notes.append(f"Rate: {pps:.1f} packets/sec, {bps:.0f} bytes/sec")

        # Encryption detection
        if inspection.application and inspection.application.protocol == "TLS":
            inspection.is_encrypted = True
            notes.append("Traffic is TLS encrypted")

        # Payload analysis
        if inspection.has_payload:
            notes.append("Connection contains application payload")
        else:
            notes.append("No application payload detected (control traffic only)")

        # Port analysis
        well_known_ports = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            21: "FTP",
            25: "SMTP",
            53: "DNS",
            110: "POP3",
            143: "IMAP",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
        }

        dst_port = inspection.dst_port
        if dst_port in well_known_ports:
            expected = well_known_ports[dst_port]
            if inspection.application:
                detected = inspection.application.protocol
                if expected.upper() != detected.upper():
                    notes.append(f"Warning: Port {dst_port} ({expected}) but detected {detected}")
            else:
                notes.append(f"Expected protocol for port {dst_port}: {expected}")

        inspection.analysis_notes = notes

    def get_hex_dump(self, flow_key: str, packet_index: int = 0) -> str:
        """Get hex dump of a specific packet in a flow."""
        with self._lock:
            inspection = self._inspections.get(flow_key)
            if not inspection or packet_index >= len(inspection.packets):
                return "(no data)"
            return inspection.packets[packet_index].hex_dump()

    def get_payload_dump(self, flow_key: str, packet_index: int = 0) -> str:
        """Get payload hex dump of a specific packet."""
        with self._lock:
            inspection = self._inspections.get(flow_key)
            if not inspection or packet_index >= len(inspection.packets):
                return "(no data)"
            return inspection.packets[packet_index].payload_hex_dump()

    def get_combined_payload(self, flow_key: str, direction: Optional[str] = None) -> bytes:
        """Get combined payload from all packets in a flow."""
        with self._lock:
            inspection = self._inspections.get(flow_key)
            if not inspection:
                return b""

            payloads = []
            for pkt in inspection.packets:
                if direction is None or pkt.direction == direction:
                    if pkt.payload:
                        payloads.append(pkt.payload)

            return b"".join(payloads)

    def get_stats(self) -> Dict:
        """Get DPI statistics."""
        with self._lock:
            return {
                "active_targets": len(self._targets),
                "inspections": len(self._inspections),
                "total_packets_captured": sum(
                    len(i.packets) for i in self._inspections.values()
                ),
            }
