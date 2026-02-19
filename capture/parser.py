"""Packet header parsing."""

import logging
from dataclasses import dataclass, field
from typing import Optional, Tuple, List

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

from config import PROTOCOL_NAMES

logger = logging.getLogger(__name__)


# DNS record type names
DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    52: "TLSA",
    65: "HTTPS",
    99: "SPF",
    257: "CAA",
}


@dataclass
class DNSQueryInfo:
    """Parsed DNS query information."""
    name: str                    # Query name (e.g., "example.com")
    qtype: int                   # Query type number
    qtype_name: str              # Query type name (e.g., "A", "AAAA")
    qclass: int = 1              # Query class (usually IN=1)


@dataclass
class DNSAnswerInfo:
    """Parsed DNS answer information."""
    name: str                    # Answer name
    rtype: int                   # Record type number
    rtype_name: str              # Record type name
    rdata: str                   # Answer data (IP, hostname, etc.)
    ttl: int = 0                 # TTL of the record


@dataclass
class DNSInfo:
    """Complete DNS packet information."""
    transaction_id: int
    is_response: bool
    is_query: bool
    opcode: int
    rcode: int                   # Response code (0=OK, 3=NXDOMAIN, etc.)
    rcode_name: str
    queries: List[DNSQueryInfo] = field(default_factory=list)
    answers: List[DNSAnswerInfo] = field(default_factory=list)
    is_truncated: bool = False
    is_authoritative: bool = False
    recursion_desired: bool = False
    recursion_available: bool = False

    @property
    def query_names(self) -> List[str]:
        """Get list of queried domain names."""
        return [q.name for q in self.queries]

    @property
    def answer_ips(self) -> List[str]:
        """Get list of IP addresses from A/AAAA answers."""
        ips = []
        for a in self.answers:
            if a.rtype in (1, 28):  # A or AAAA
                ips.append(a.rdata)
        return ips


# DNS response codes
DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


@dataclass
class ParsedPacket:
    """Parsed packet header information."""

    timestamp: float
    src_mac: Optional[str]
    dst_mac: Optional[str]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    protocol_name: str
    ttl: int
    length: int
    flags: str
    seq: Optional[int] = None
    ack: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    dns: Optional[DNSInfo] = None  # DNS info if this is a DNS packet
    tags: List[str] = field(default_factory=list)  # Detection/classification tags

    @property
    def flow_key(self) -> Tuple[str, str, int, int, int]:
        """Return the 5-tuple flow key."""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    @property
    def reverse_flow_key(self) -> Tuple[str, str, int, int, int]:
        """Return the reverse 5-tuple flow key."""
        return (self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)


class PacketParser:
    """Parse packet headers from scapy packets."""

    @staticmethod
    def parse(packet: Packet) -> Optional[ParsedPacket]:
        """Parse a scapy packet into a ParsedPacket."""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]

        # Extract Ethernet layer if present
        src_mac = None
        dst_mac = None
        if packet.haslayer(Ether):
            ether_layer = packet[Ether]
            src_mac = ether_layer.src
            dst_mac = ether_layer.dst

        # Default values
        src_port = 0
        dst_port = 0
        flags = ""
        seq = None
        ack = None
        icmp_type = None
        icmp_code = None
        dns_info = None

        protocol = ip_layer.proto
        protocol_name = PROTOCOL_NAMES.get(protocol, f"Proto-{protocol}")

        # Parse transport layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = str(tcp_layer.flags)
            seq = tcp_layer.seq
            ack = tcp_layer.ack
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            # Check for DNS
            if packet.haslayer(DNS):
                dns_info = PacketParser._parse_dns(packet[DNS])
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            # Use ICMP type/code as pseudo-ports for flow tracking
            src_port = icmp_type
            dst_port = icmp_code

        return ParsedPacket(
            timestamp=float(packet.time),
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            protocol_name=protocol_name,
            ttl=ip_layer.ttl,
            length=len(packet),
            flags=flags,
            seq=seq,
            ack=ack,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            dns=dns_info,
        )

    @staticmethod
    def _parse_dns(dns_layer: DNS) -> Optional[DNSInfo]:
        """Parse DNS layer into DNSInfo."""
        try:
            # Basic DNS header fields
            transaction_id = dns_layer.id
            is_response = bool(dns_layer.qr)  # QR=1 means response
            is_query = not is_response
            opcode = dns_layer.opcode
            rcode = dns_layer.rcode
            rcode_name = DNS_RCODES.get(rcode, f"RCODE-{rcode}")

            # Flags
            is_truncated = bool(dns_layer.tc)
            is_authoritative = bool(dns_layer.aa)
            recursion_desired = bool(dns_layer.rd)
            recursion_available = bool(dns_layer.ra)

            # Parse queries
            queries = []
            if dns_layer.qdcount and dns_layer.qd:
                qd = dns_layer.qd
                # Handle single query or list
                if isinstance(qd, DNSQR):
                    qd = [qd]
                for q in qd:
                    if hasattr(q, 'qname'):
                        qname = q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname)
                        # Remove trailing dot
                        qname = qname.rstrip('.')
                        qtype = q.qtype
                        qtype_name = DNS_TYPES.get(qtype, f"TYPE{qtype}")
                        queries.append(DNSQueryInfo(
                            name=qname,
                            qtype=qtype,
                            qtype_name=qtype_name,
                            qclass=q.qclass,
                        ))

            # Parse answers
            answers = []
            if dns_layer.ancount and dns_layer.an:
                an = dns_layer.an
                # Handle single answer or list
                if isinstance(an, DNSRR):
                    an = [an]
                for a in an:
                    if hasattr(a, 'rrname'):
                        rrname = a.rrname.decode() if isinstance(a.rrname, bytes) else str(a.rrname)
                        rrname = rrname.rstrip('.')
                        rtype = a.type
                        rtype_name = DNS_TYPES.get(rtype, f"TYPE{rtype}")

                        # Format rdata based on type
                        rdata = ""
                        if hasattr(a, 'rdata'):
                            if isinstance(a.rdata, bytes):
                                try:
                                    rdata = a.rdata.decode()
                                except UnicodeDecodeError:
                                    rdata = a.rdata.hex()
                            else:
                                rdata = str(a.rdata)
                            rdata = rdata.rstrip('.')

                        answers.append(DNSAnswerInfo(
                            name=rrname,
                            rtype=rtype,
                            rtype_name=rtype_name,
                            rdata=rdata,
                            ttl=a.ttl if hasattr(a, 'ttl') else 0,
                        ))

            return DNSInfo(
                transaction_id=transaction_id,
                is_response=is_response,
                is_query=is_query,
                opcode=opcode,
                rcode=rcode,
                rcode_name=rcode_name,
                queries=queries,
                answers=answers,
                is_truncated=is_truncated,
                is_authoritative=is_authoritative,
                recursion_desired=recursion_desired,
                recursion_available=recursion_available,
            )
        except Exception as e:
            logger.debug(f"Failed to parse DNS packet: {e}")
            return None
