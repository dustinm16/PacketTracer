"""Traffic classification and purpose detection."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum, auto
from collections import defaultdict
import threading
import re

from tracking.flow import Flow
from capture.parser import ParsedPacket


class TrafficCategory(Enum):
    """High-level traffic categories."""
    WEB_BROWSING = auto()
    VIDEO_STREAMING = auto()
    AUDIO_STREAMING = auto()
    GAMING = auto()
    VOIP = auto()
    FILE_TRANSFER = auto()
    EMAIL = auto()
    DNS = auto()
    DATABASE = auto()
    REMOTE_ACCESS = auto()
    VPN_TUNNEL = auto()
    P2P = auto()
    ENCRYPTED = auto()
    IOT = auto()
    NETWORK_MGMT = auto()
    HANDSHAKE = auto()
    KEEPALIVE = auto()
    UNKNOWN = auto()


@dataclass
class TrafficClassification:
    """Classification result for a flow."""
    category: TrafficCategory
    confidence: float  # 0.0 to 1.0
    subcategory: str = ""
    service: str = ""
    is_encrypted: bool = False
    description: str = ""


class TrafficClassifier:
    """Classifies network traffic by purpose and type."""

    # Port-based service detection
    PORT_SERVICES: Dict[int, Tuple[TrafficCategory, str, str]] = {
        # Web
        80: (TrafficCategory.WEB_BROWSING, "HTTP", "Web browsing"),
        443: (TrafficCategory.ENCRYPTED, "HTTPS", "Encrypted web"),
        8080: (TrafficCategory.WEB_BROWSING, "HTTP-Alt", "Web proxy/alt"),
        8443: (TrafficCategory.ENCRYPTED, "HTTPS-Alt", "Encrypted web alt"),

        # Streaming
        554: (TrafficCategory.VIDEO_STREAMING, "RTSP", "Real-time streaming"),
        1935: (TrafficCategory.VIDEO_STREAMING, "RTMP", "Flash streaming"),

        # Email
        25: (TrafficCategory.EMAIL, "SMTP", "Email sending"),
        110: (TrafficCategory.EMAIL, "POP3", "Email retrieval"),
        143: (TrafficCategory.EMAIL, "IMAP", "Email access"),
        465: (TrafficCategory.EMAIL, "SMTPS", "Secure email sending"),
        587: (TrafficCategory.EMAIL, "SMTP", "Email submission"),
        993: (TrafficCategory.EMAIL, "IMAPS", "Secure email access"),
        995: (TrafficCategory.EMAIL, "POP3S", "Secure email retrieval"),

        # File Transfer
        20: (TrafficCategory.FILE_TRANSFER, "FTP-Data", "FTP data transfer"),
        21: (TrafficCategory.FILE_TRANSFER, "FTP", "FTP control"),
        22: (TrafficCategory.REMOTE_ACCESS, "SSH", "Secure shell/SFTP"),
        69: (TrafficCategory.FILE_TRANSFER, "TFTP", "Trivial FTP"),
        115: (TrafficCategory.FILE_TRANSFER, "SFTP", "Simple FTP"),
        445: (TrafficCategory.FILE_TRANSFER, "SMB", "Windows file sharing"),

        # DNS
        53: (TrafficCategory.DNS, "DNS", "Domain resolution"),
        853: (TrafficCategory.DNS, "DoT", "DNS over TLS"),

        # Remote Access
        23: (TrafficCategory.REMOTE_ACCESS, "Telnet", "Telnet access"),
        3389: (TrafficCategory.REMOTE_ACCESS, "RDP", "Remote desktop"),
        5900: (TrafficCategory.REMOTE_ACCESS, "VNC", "VNC remote desktop"),
        5938: (TrafficCategory.REMOTE_ACCESS, "TeamViewer", "TeamViewer"),

        # VoIP
        5060: (TrafficCategory.VOIP, "SIP", "VoIP signaling"),
        5061: (TrafficCategory.VOIP, "SIPS", "Secure VoIP signaling"),

        # Database
        1433: (TrafficCategory.DATABASE, "MSSQL", "MS SQL Server"),
        1521: (TrafficCategory.DATABASE, "Oracle", "Oracle DB"),
        3306: (TrafficCategory.DATABASE, "MySQL", "MySQL/MariaDB"),
        5432: (TrafficCategory.DATABASE, "PostgreSQL", "PostgreSQL"),
        6379: (TrafficCategory.DATABASE, "Redis", "Redis cache"),
        27017: (TrafficCategory.DATABASE, "MongoDB", "MongoDB"),

        # VPN
        500: (TrafficCategory.VPN_TUNNEL, "IKE", "IPsec VPN"),
        1194: (TrafficCategory.VPN_TUNNEL, "OpenVPN", "OpenVPN"),
        1701: (TrafficCategory.VPN_TUNNEL, "L2TP", "L2TP VPN"),
        1723: (TrafficCategory.VPN_TUNNEL, "PPTP", "PPTP VPN"),
        4500: (TrafficCategory.VPN_TUNNEL, "IPsec-NAT", "IPsec NAT-T"),
        51820: (TrafficCategory.VPN_TUNNEL, "WireGuard", "WireGuard VPN"),

        # Network Management
        67: (TrafficCategory.NETWORK_MGMT, "DHCP", "DHCP server"),
        68: (TrafficCategory.NETWORK_MGMT, "DHCP", "DHCP client"),
        123: (TrafficCategory.NETWORK_MGMT, "NTP", "Time sync"),
        161: (TrafficCategory.NETWORK_MGMT, "SNMP", "Network monitoring"),
        162: (TrafficCategory.NETWORK_MGMT, "SNMP-Trap", "SNMP alerts"),
        514: (TrafficCategory.NETWORK_MGMT, "Syslog", "System logging"),

        # Gaming (common ports)
        3478: (TrafficCategory.GAMING, "STUN", "Gaming/STUN"),
        3479: (TrafficCategory.GAMING, "STUN", "Gaming/STUN"),
        3724: (TrafficCategory.GAMING, "Blizzard", "Blizzard games"),
        6112: (TrafficCategory.GAMING, "Blizzard", "Blizzard games"),
        27015: (TrafficCategory.GAMING, "Steam", "Steam gaming"),
        27016: (TrafficCategory.GAMING, "Steam", "Steam gaming"),

        # P2P
        6881: (TrafficCategory.P2P, "BitTorrent", "BitTorrent"),
        6889: (TrafficCategory.P2P, "BitTorrent", "BitTorrent"),
    }

    # Known streaming service IP patterns (simplified)
    STREAMING_DOMAINS = {
        "netflix", "youtube", "googlevideo", "twitch", "akamai",
        "cloudfront", "hulu", "spotify", "soundcloud", "deezer",
        "pandora", "primevideo", "disneyplus", "hbomax", "peacock",
    }

    def __init__(self):
        self._lock = threading.Lock()
        self._flow_classifications: Dict[str, TrafficClassification] = {}

        # Statistics
        self.category_counts: Dict[TrafficCategory, int] = defaultdict(int)
        self.category_bytes: Dict[TrafficCategory, int] = defaultdict(int)

    def _get_flow_key(self, flow: Flow) -> str:
        """Generate a unique key for a flow."""
        return f"{flow.src_ip}:{flow.src_port}-{flow.dst_ip}:{flow.dst_port}-{flow.protocol}"

    def _classify_by_port(self, port: int) -> Optional[Tuple[TrafficCategory, str, str]]:
        """Classify by known port."""
        return self.PORT_SERVICES.get(port)

    def _detect_handshake(self, flow: Flow) -> bool:
        """Detect if flow is a connection handshake."""
        # Few packets, small size, balanced send/recv
        if flow.total_packets <= 6 and flow.total_bytes < 1000:
            if flow.packets_sent > 0 and flow.packets_recv > 0:
                return True
        return False

    def _detect_keepalive(self, flow: Flow) -> bool:
        """Detect keepalive traffic."""
        # Very small packets, roughly equal distribution
        if flow.total_packets > 0:
            avg_size = flow.total_bytes / flow.total_packets
            if avg_size < 100 and flow.duration > 30:
                return True
        return False

    def _detect_streaming(self, flow: Flow) -> bool:
        """Detect streaming traffic patterns."""
        # High bytes, predominantly one direction
        if flow.total_bytes > 100000:  # > 100KB
            if flow.bytes_recv > flow.bytes_sent * 5:  # Mostly receiving
                if flow.total_packets > 100:
                    return True
        return False

    def _detect_encrypted(self, port: int, protocol: str) -> bool:
        """Check if traffic is likely encrypted."""
        encrypted_ports = {443, 465, 587, 636, 853, 990, 992, 993, 995, 8443}
        return port in encrypted_ports or protocol in ["HTTPS", "SSH", "SFTP"]

    def _detect_voip(self, flow: Flow) -> bool:
        """Detect VoIP traffic patterns."""
        if flow.protocol_name == "UDP":
            if flow.total_packets > 50:
                avg_size = flow.total_bytes / flow.total_packets
                # VoIP typically has small, consistent packet sizes
                if 100 < avg_size < 300:
                    # Roughly balanced bidirectional
                    if 0.3 < (flow.packets_sent / max(1, flow.total_packets)) < 0.7:
                        return True
        return False

    def classify_flow(self, flow: Flow) -> TrafficClassification:
        """Classify a network flow."""
        flow_key = self._get_flow_key(flow)

        # Check cache
        with self._lock:
            if flow_key in self._flow_classifications:
                return self._flow_classifications[flow_key]

        # Start classification
        category = TrafficCategory.UNKNOWN
        confidence = 0.5
        subcategory = ""
        service = ""
        is_encrypted = False
        description = ""

        # Check both ports
        for port in [flow.dst_port, flow.src_port]:
            port_info = self._classify_by_port(port)
            if port_info:
                category, service, description = port_info
                confidence = 0.8
                is_encrypted = self._detect_encrypted(port, service)
                break

        # Pattern-based detection (can override port-based)
        if self._detect_handshake(flow):
            if category == TrafficCategory.UNKNOWN:
                category = TrafficCategory.HANDSHAKE
                description = "Connection establishment"
                confidence = 0.7
            else:
                subcategory = "handshake"

        elif self._detect_keepalive(flow):
            if category == TrafficCategory.UNKNOWN:
                category = TrafficCategory.KEEPALIVE
                description = "Connection keepalive"
                confidence = 0.6

        elif self._detect_streaming(flow):
            category = TrafficCategory.VIDEO_STREAMING
            description = "Streaming media"
            confidence = 0.7
            subcategory = "media"

        elif self._detect_voip(flow):
            category = TrafficCategory.VOIP
            description = "Voice/Video call"
            confidence = 0.7

        # Protocol-specific adjustments
        if flow.protocol_name == "ICMP":
            category = TrafficCategory.NETWORK_MGMT
            service = "ICMP"
            description = "Network diagnostic"
            confidence = 0.9

        # DNS detection
        if flow.dst_port == 53 or flow.src_port == 53:
            category = TrafficCategory.DNS
            service = "DNS"
            description = "Domain name resolution"
            confidence = 0.95

        # Final encrypted check
        if not is_encrypted and flow.dst_port in [443, 8443]:
            is_encrypted = True

        classification = TrafficClassification(
            category=category,
            confidence=confidence,
            subcategory=subcategory,
            service=service,
            is_encrypted=is_encrypted,
            description=description,
        )

        # Cache and update stats
        with self._lock:
            self._flow_classifications[flow_key] = classification
            self.category_counts[category] += 1
            self.category_bytes[category] += flow.total_bytes

        return classification

    def get_category_stats(self) -> Dict[TrafficCategory, Tuple[int, int]]:
        """Get count and bytes per category."""
        with self._lock:
            return {
                cat: (self.category_counts[cat], self.category_bytes[cat])
                for cat in TrafficCategory
                if self.category_counts[cat] > 0
            }

    def get_classification(self, flow: Flow) -> Optional[TrafficClassification]:
        """Get the stored classification for a flow."""
        key = self._get_flow_key(flow)
        with self._lock:
            return self._flow_classifications.get(key)

    def get_category_name(self, category: TrafficCategory) -> str:
        """Get human-readable category name."""
        names = {
            TrafficCategory.WEB_BROWSING: "Web Browsing",
            TrafficCategory.VIDEO_STREAMING: "Video Streaming",
            TrafficCategory.AUDIO_STREAMING: "Audio Streaming",
            TrafficCategory.GAMING: "Gaming",
            TrafficCategory.VOIP: "VoIP/Calling",
            TrafficCategory.FILE_TRANSFER: "File Transfer",
            TrafficCategory.EMAIL: "Email",
            TrafficCategory.DNS: "DNS Lookup",
            TrafficCategory.DATABASE: "Database",
            TrafficCategory.REMOTE_ACCESS: "Remote Access",
            TrafficCategory.VPN_TUNNEL: "VPN/Tunnel",
            TrafficCategory.P2P: "Peer-to-Peer",
            TrafficCategory.ENCRYPTED: "Encrypted (TLS)",
            TrafficCategory.IOT: "IoT Device",
            TrafficCategory.NETWORK_MGMT: "Network Mgmt",
            TrafficCategory.HANDSHAKE: "Handshake",
            TrafficCategory.KEEPALIVE: "Keepalive",
            TrafficCategory.UNKNOWN: "Unknown",
        }
        return names.get(category, str(category))

    def clear(self) -> None:
        """Clear all classifications and stats."""
        with self._lock:
            self._flow_classifications.clear()
            self.category_counts.clear()
            self.category_bytes.clear()
