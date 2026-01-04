"""Packet type analysis panel."""

from typing import Dict, List, Optional, Any
from collections import defaultdict
from dataclasses import dataclass, field
import threading
import time

from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.columns import Columns
from rich.text import Text

from tracking.flow import Flow, FlowTracker
from tracking.classifier import TrafficClassifier, TrafficCategory, TrafficClassification
from capture.parser import ParsedPacket
from utils.network import format_bytes, format_packets


@dataclass
class ProtocolStats:
    """Statistics for a protocol."""
    packets: int = 0
    bytes: int = 0
    flows: int = 0


@dataclass
class PortStats:
    """Statistics for a port/service."""
    port: int = 0
    protocol: str = ""
    packets: int = 0
    bytes: int = 0
    service_name: str = ""


@dataclass
class TCPFlagStats:
    """Statistics for TCP flags."""
    syn: int = 0
    syn_ack: int = 0
    ack: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0
    urg: int = 0


class PacketAnalyzer:
    """Analyzes packet types and patterns."""

    # Common service port mappings
    KNOWN_PORTS = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
        119: "NNTP", 123: "NTP", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
        194: "IRC", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
        587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB",
    }

    def __init__(self):
        self._lock = threading.Lock()

        # Protocol statistics
        self.protocol_stats: Dict[str, ProtocolStats] = defaultdict(ProtocolStats)

        # Port statistics (top ports by traffic)
        self.port_stats: Dict[int, PortStats] = {}

        # TCP flag analysis
        self.tcp_flags = TCPFlagStats()

        # ICMP type analysis
        self.icmp_types: Dict[int, int] = defaultdict(int)

        # Packet size distribution
        self.size_buckets: Dict[str, int] = {
            "tiny (<64B)": 0,
            "small (64-127B)": 0,
            "medium (128-511B)": 0,
            "large (512-1023B)": 0,
            "jumbo (1024-1499B)": 0,
            "max (1500B+)": 0,
        }

        # Time-based stats
        self.packets_per_second: List[int] = [0] * 60  # Last 60 seconds
        self.bytes_per_second: List[int] = [0] * 60
        self._last_second: int = 0

    def process_packet(self, packet: ParsedPacket) -> None:
        """Process a packet for analysis."""
        with self._lock:
            # Protocol stats
            proto = packet.protocol_name
            self.protocol_stats[proto].packets += 1
            self.protocol_stats[proto].bytes += packet.length

            # Port stats
            for port in [packet.src_port, packet.dst_port]:
                if port and port > 0:
                    if port not in self.port_stats:
                        self.port_stats[port] = PortStats(
                            port=port,
                            protocol=proto,
                            service_name=self.KNOWN_PORTS.get(port, ""),
                        )
                    self.port_stats[port].packets += 1
                    self.port_stats[port].bytes += packet.length

            # TCP flag analysis
            if packet.flags:
                flags = packet.flags.upper()
                if 'S' in flags and 'A' not in flags:
                    self.tcp_flags.syn += 1
                if 'S' in flags and 'A' in flags:
                    self.tcp_flags.syn_ack += 1
                if 'A' in flags and 'S' not in flags:
                    self.tcp_flags.ack += 1
                if 'F' in flags:
                    self.tcp_flags.fin += 1
                if 'R' in flags:
                    self.tcp_flags.rst += 1
                if 'P' in flags:
                    self.tcp_flags.psh += 1
                if 'U' in flags:
                    self.tcp_flags.urg += 1

            # ICMP type analysis
            if packet.icmp_type is not None:
                self.icmp_types[packet.icmp_type] += 1

            # Packet size distribution
            size = packet.length
            if size < 64:
                self.size_buckets["tiny (<64B)"] += 1
            elif size < 128:
                self.size_buckets["small (64-127B)"] += 1
            elif size < 512:
                self.size_buckets["medium (128-511B)"] += 1
            elif size < 1024:
                self.size_buckets["large (512-1023B)"] += 1
            elif size < 1500:
                self.size_buckets["jumbo (1024-1499B)"] += 1
            else:
                self.size_buckets["max (1500B+)"] += 1

            # Time-based stats
            current_second = int(time.time()) % 60
            if current_second != self._last_second:
                # Clear old buckets if we skipped any seconds
                if self._last_second != 0:
                    steps = (current_second - self._last_second) % 60
                    for i in range(steps):
                        idx = (self._last_second + i + 1) % 60
                        self.packets_per_second[idx] = 0
                        self.bytes_per_second[idx] = 0
                self._last_second = current_second

            self.packets_per_second[current_second] += 1
            self.bytes_per_second[current_second] += packet.length

    def get_top_ports(self, n: int = 10) -> List[PortStats]:
        """Get top N ports by bytes."""
        with self._lock:
            sorted_ports = sorted(
                self.port_stats.values(),
                key=lambda p: p.bytes,
                reverse=True
            )
            return sorted_ports[:n]

    def get_protocol_breakdown(self) -> Dict[str, ProtocolStats]:
        """Get protocol breakdown."""
        with self._lock:
            return dict(self.protocol_stats)

    def get_avg_packets_per_second(self) -> float:
        """Get average packets per second over last minute."""
        with self._lock:
            return sum(self.packets_per_second) / 60

    def get_avg_bytes_per_second(self) -> float:
        """Get average bytes per second over last minute."""
        with self._lock:
            return sum(self.bytes_per_second) / 60

    def clear(self) -> None:
        """Clear all statistics."""
        with self._lock:
            self.protocol_stats.clear()
            self.port_stats.clear()
            self.tcp_flags = TCPFlagStats()
            self.icmp_types.clear()
            for key in self.size_buckets:
                self.size_buckets[key] = 0
            self.packets_per_second = [0] * 60
            self.bytes_per_second = [0] * 60


class AnalysisPanel:
    """Panel displaying packet type analysis."""

    ICMP_TYPE_NAMES = {
        0: "Echo Reply",
        3: "Dest Unreachable",
        4: "Source Quench",
        5: "Redirect",
        8: "Echo Request",
        9: "Router Advert",
        10: "Router Solicit",
        11: "Time Exceeded",
        12: "Parameter Problem",
        13: "Timestamp",
        14: "Timestamp Reply",
    }

    # Category display colors
    CATEGORY_COLORS = {
        TrafficCategory.WEB_BROWSING: "blue",
        TrafficCategory.VIDEO_STREAMING: "magenta",
        TrafficCategory.AUDIO_STREAMING: "magenta",
        TrafficCategory.GAMING: "green",
        TrafficCategory.VOIP: "cyan",
        TrafficCategory.FILE_TRANSFER: "yellow",
        TrafficCategory.EMAIL: "blue",
        TrafficCategory.DNS: "dim",
        TrafficCategory.DATABASE: "red",
        TrafficCategory.REMOTE_ACCESS: "yellow",
        TrafficCategory.VPN_TUNNEL: "green",
        TrafficCategory.P2P: "red",
        TrafficCategory.ENCRYPTED: "cyan",
        TrafficCategory.IOT: "dim",
        TrafficCategory.NETWORK_MGMT: "dim",
        TrafficCategory.HANDSHAKE: "dim",
        TrafficCategory.KEEPALIVE: "dim",
        TrafficCategory.UNKNOWN: "white",
    }

    def __init__(self, analyzer: PacketAnalyzer, classifier: Optional[TrafficClassifier] = None):
        self.analyzer = analyzer
        self.classifier = classifier or TrafficClassifier()
        self.show_details = False
        self._selected_flows: Optional[List[Flow]] = None

    def set_selected_flows(self, flows: Optional[List[Flow]]) -> None:
        """Set selected flows to filter classification stats."""
        self._selected_flows = flows if flows else None

    def _get_protocol_stats_from_flows(self) -> Dict[str, ProtocolStats]:
        """Calculate protocol stats from selected flows."""
        if not self._selected_flows:
            return {}
        stats = defaultdict(lambda: ProtocolStats())
        for flow in self._selected_flows:
            proto = flow.protocol_name
            stats[proto].packets += flow.total_packets
            stats[proto].bytes += flow.total_bytes
            stats[proto].flows += 1
        return dict(stats)

    def _get_port_stats_from_flows(self) -> List[PortStats]:
        """Calculate port stats from selected flows."""
        if not self._selected_flows:
            return []
        port_data: Dict[int, PortStats] = {}
        for flow in self._selected_flows:
            for port in [flow.src_port, flow.dst_port]:
                if port and port > 0:
                    if port not in port_data:
                        port_data[port] = PortStats(
                            port=port,
                            protocol=flow.protocol_name,
                            service_name=self.analyzer.KNOWN_PORTS.get(port, ""),
                        )
                    port_data[port].packets += flow.total_packets
                    port_data[port].bytes += flow.total_bytes
        return sorted(port_data.values(), key=lambda p: p.bytes, reverse=True)

    def _render_protocol_breakdown(self) -> Panel:
        """Render protocol breakdown."""
        if self._selected_flows:
            stats = self._get_protocol_stats_from_flows()
            title = f"[bold]Protocols[/bold] [yellow]({len(self._selected_flows)} flows)[/yellow]"
        else:
            stats = self.analyzer.get_protocol_breakdown()
            title = "[bold]Protocols[/bold]"

        if not stats:
            return Panel("No data", title=title, border_style="blue")

        table = Table(show_header=True, header_style="bold", box=None, expand=True)
        table.add_column("Protocol", style="magenta")
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("", width=20)  # Bar

        total_bytes = sum(s.bytes for s in stats.values())
        sorted_stats = sorted(stats.items(), key=lambda x: x[1].bytes, reverse=True)

        for proto, stat in sorted_stats:
            pct = (stat.bytes / total_bytes * 100) if total_bytes > 0 else 0
            bar_len = int(pct / 5)  # 20 chars = 100%
            bar = "█" * bar_len

            table.add_row(
                proto,
                format_packets(stat.packets),
                format_bytes(stat.bytes),
                f"[green]{bar}[/green] {pct:.1f}%",
            )

        return Panel(table, title=title, border_style="blue")

    def _render_top_ports(self) -> Panel:
        """Render top ports by traffic."""
        if self._selected_flows:
            ports = self._get_port_stats_from_flows()[:10]
            title = f"[bold]Top Ports[/bold] [yellow]({len(self._selected_flows)} flows)[/yellow]"
        else:
            ports = self.analyzer.get_top_ports(10)
            title = "[bold]Top Ports[/bold]"

        if not ports:
            return Panel("No data", title=title, border_style="blue")

        table = Table(show_header=True, header_style="bold", box=None, expand=True)
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Service", style="yellow")
        table.add_column("Proto", style="magenta")
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right")

        for port in ports:
            table.add_row(
                str(port.port),
                port.service_name or "-",
                port.protocol,
                format_packets(port.packets),
                format_bytes(port.bytes),
            )

        return Panel(table, title=title, border_style="blue")

    def _render_tcp_flags(self) -> Panel:
        """Render TCP flag analysis."""
        flags = self.analyzer.tcp_flags
        total = flags.syn + flags.syn_ack + flags.ack + flags.fin + flags.rst

        if total == 0:
            return Panel("No TCP data", title="[bold]TCP Flags[/bold]", border_style="blue")

        lines = [
            f"[cyan]SYN:[/cyan]     {flags.syn:>8}  (new connections)",
            f"[cyan]SYN+ACK:[/cyan] {flags.syn_ack:>8}  (connection accepts)",
            f"[cyan]ACK:[/cyan]     {flags.ack:>8}  (acknowledgements)",
            f"[cyan]FIN:[/cyan]     {flags.fin:>8}  (connection closes)",
            f"[cyan]RST:[/cyan]     {flags.rst:>8}  (resets/errors)",
            f"[cyan]PSH:[/cyan]     {flags.psh:>8}  (data push)",
        ]

        # Connection health indicator
        if flags.rst > flags.syn * 0.1:
            lines.append("")
            lines.append("[yellow]High RST ratio - possible connection issues[/yellow]")

        return Panel("\n".join(lines), title="[bold]TCP Flags[/bold]", border_style="blue")

    def _render_icmp_types(self) -> Panel:
        """Render ICMP type breakdown."""
        icmp = self.analyzer.icmp_types

        if not icmp:
            return Panel("No ICMP data", title="[bold]ICMP Types[/bold]", border_style="blue")

        lines = []
        sorted_icmp = sorted(icmp.items(), key=lambda x: x[1], reverse=True)

        for icmp_type, count in sorted_icmp[:8]:
            name = self.ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")
            lines.append(f"[cyan]{name:20}[/cyan] {count:>8}")

        return Panel("\n".join(lines), title="[bold]ICMP Types[/bold]", border_style="blue")

    def _render_size_distribution(self) -> Panel:
        """Render packet size distribution."""
        sizes = self.analyzer.size_buckets
        total = sum(sizes.values())

        if total == 0:
            return Panel("No data", title="[bold]Packet Sizes[/bold]", border_style="blue")

        lines = []
        for bucket, count in sizes.items():
            pct = (count / total * 100) if total > 0 else 0
            bar_len = int(pct / 5)
            bar = "█" * bar_len
            lines.append(f"[cyan]{bucket:18}[/cyan] [green]{bar:20}[/green] {pct:5.1f}%")

        return Panel("\n".join(lines), title="[bold]Packet Sizes[/bold]", border_style="blue")

    def _render_throughput(self) -> Panel:
        """Render throughput stats."""
        pps = self.analyzer.get_avg_packets_per_second()
        bps = self.analyzer.get_avg_bytes_per_second()

        lines = [
            f"[cyan]Packets/sec:[/cyan] {pps:.1f}",
            f"[cyan]Bytes/sec:[/cyan]   {format_bytes(int(bps))}/s",
            f"[cyan]Bits/sec:[/cyan]    {format_bytes(int(bps * 8))}ps",
        ]

        return Panel("\n".join(lines), title="[bold]Throughput (60s avg)[/bold]", border_style="blue")

    def _get_category_stats_filtered(self) -> Dict[TrafficCategory, tuple]:
        """Get category stats, filtering by selected flows if any."""
        if not self._selected_flows:
            return self.classifier.get_category_stats()

        # Calculate stats from selected flows only
        stats = defaultdict(lambda: [0, 0])  # [count, bytes]
        for flow in self._selected_flows:
            classification = self.classifier.get_classification(flow)
            if classification:
                cat = classification.category
                stats[cat][0] += 1
                stats[cat][1] += flow.total_bytes

        return {k: tuple(v) for k, v in stats.items()}

    def _render_traffic_classification(self) -> Panel:
        """Render traffic purpose classification."""
        stats = self._get_category_stats_filtered()

        # Title with selection indicator
        if self._selected_flows:
            title = f"[bold]Traffic Purpose[/bold] [yellow](Selected: {len(self._selected_flows)})[/yellow]"
        else:
            title = "[bold]Traffic Purpose Analysis[/bold]"

        if not stats:
            return Panel("No data - analyzing traffic...", title=title, border_style="green")

        table = Table(show_header=True, header_style="bold", box=None, expand=True)
        table.add_column("Purpose", style="white")
        table.add_column("Flows", justify="right", width=8)
        table.add_column("Bytes", justify="right", width=12)
        table.add_column("", width=15)  # Bar

        total_bytes = sum(b for _, b in stats.values())
        sorted_stats = sorted(stats.items(), key=lambda x: x[1][1], reverse=True)

        for category, (count, bytes_) in sorted_stats[:10]:
            name = self.classifier.get_category_name(category)
            color = self.CATEGORY_COLORS.get(category, "white")
            pct = (bytes_ / total_bytes * 100) if total_bytes > 0 else 0
            bar_len = int(pct / 7)  # ~15 chars = 100%
            bar = "█" * bar_len

            table.add_row(
                f"[{color}]{name}[/{color}]",
                str(count),
                format_bytes(bytes_),
                f"[{color}]{bar}[/{color}] {pct:.0f}%",
            )

        return Panel(table, title=title, border_style="green")

    def _render_encryption_summary(self) -> Panel:
        """Render encryption status summary."""
        stats = self._get_category_stats_filtered()

        encrypted_count = 0
        encrypted_bytes = 0
        unencrypted_count = 0
        unencrypted_bytes = 0

        encrypted_categories = {
            TrafficCategory.ENCRYPTED,
            TrafficCategory.VPN_TUNNEL,
        }

        for category, (count, bytes_) in stats.items():
            if category in encrypted_categories:
                encrypted_count += count
                encrypted_bytes += bytes_
            else:
                unencrypted_count += count
                unencrypted_bytes += bytes_

        total_count = encrypted_count + unencrypted_count
        total_bytes = encrypted_bytes + unencrypted_bytes

        enc_pct = (encrypted_bytes / total_bytes * 100) if total_bytes > 0 else 0

        # Build visual bar
        enc_bar_len = int(enc_pct / 5)
        unenc_bar_len = 20 - enc_bar_len

        lines = [
            f"[bold]Encryption Status[/bold]",
            "",
            f"[green]{'█' * enc_bar_len}[/green][red]{'█' * unenc_bar_len}[/red]",
            "",
            f"[green]Encrypted:[/green]   {encrypted_count:>6} flows  {format_bytes(encrypted_bytes):>10}  ({enc_pct:.1f}%)",
            f"[red]Unencrypted:[/red] {unencrypted_count:>6} flows  {format_bytes(unencrypted_bytes):>10}  ({100-enc_pct:.1f}%)",
        ]

        return Panel("\n".join(lines), title="[bold]Security[/bold]", border_style="yellow")

    def render(self) -> RenderableType:
        """Render the analysis panel."""
        # Top row: traffic classification and encryption
        top_row = Columns([
            self._render_traffic_classification(),
            self._render_encryption_summary(),
        ], expand=True)

        # Second row: protocols and ports
        second_row = Columns([
            self._render_protocol_breakdown(),
            self._render_top_ports(),
        ], expand=True)

        # Third row: TCP flags and ICMP types
        third_row = Columns([
            self._render_tcp_flags(),
            self._render_icmp_types(),
        ], expand=True)

        # Bottom row: sizes and throughput
        bottom_row = Columns([
            self._render_size_distribution(),
            self._render_throughput(),
        ], expand=True)

        return Group(top_row, second_row, third_row, bottom_row)
