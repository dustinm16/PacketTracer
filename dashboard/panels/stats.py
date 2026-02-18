"""Statistics panel."""

from typing import Dict, Optional, List
from collections import defaultdict
from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.columns import Columns

from tracking.flow import FlowTracker, Flow
from tracking.dns_tracker import DNSTracker
from geo.resolver import GeoResolver
from geo.dns_resolver import DNSResolver
from utils.network import format_bytes, format_packets


class StatsPanel:
    """Panel displaying aggregate statistics."""

    def __init__(
        self,
        flow_tracker: FlowTracker,
        geo_resolver: Optional[GeoResolver] = None,
        dns_resolver: Optional[DNSResolver] = None,
        dns_tracker: Optional[DNSTracker] = None,
    ):
        self.flow_tracker = flow_tracker
        self.geo_resolver = geo_resolver
        self.dns_resolver = dns_resolver
        self.dns_tracker = dns_tracker
        self._selected_flows: Optional[List[Flow]] = None

    def set_selected_flows(self, flows: Optional[List[Flow]]) -> None:
        """Set the selected flows to filter stats by."""
        self._selected_flows = flows if flows else None

    def _get_flows(self) -> List[Flow]:
        """Get flows to analyze - selected if any, otherwise all."""
        if self._selected_flows:
            return self._selected_flows
        return self.flow_tracker.get_flows()

    def _get_protocol_stats(self) -> Dict[str, Dict[str, int]]:
        """Get statistics by protocol."""
        stats = defaultdict(lambda: {"flows": 0, "bytes": 0, "packets": 0})
        for flow in self._get_flows():
            proto = flow.protocol_name
            stats[proto]["flows"] += 1
            stats[proto]["bytes"] += flow.total_bytes
            stats[proto]["packets"] += flow.total_packets
        return dict(stats)

    def _get_country_stats(self) -> Dict[str, int]:
        """Get flow count by country."""
        stats = defaultdict(int)
        for flow in self._get_flows():
            if flow.dst_geo and hasattr(flow.dst_geo, "country") and flow.dst_geo.country:
                stats[flow.dst_geo.country] += 1
            elif flow.dst_geo and isinstance(flow.dst_geo, dict) and flow.dst_geo.get("country"):
                stats[flow.dst_geo["country"]] += 1
        return dict(stats)

    def _get_isp_stats(self) -> Dict[str, int]:
        """Get flow count by ISP."""
        stats = defaultdict(int)
        for flow in self._get_flows():
            if flow.dst_geo and hasattr(flow.dst_geo, "isp") and flow.dst_geo.isp:
                stats[flow.dst_geo.isp] += 1
            elif flow.dst_geo and isinstance(flow.dst_geo, dict) and flow.dst_geo.get("isp"):
                stats[flow.dst_geo["isp"]] += 1
        return dict(stats)

    def _render_overview(self) -> Panel:
        """Render overview statistics."""
        flows = self._get_flows()
        total_bytes = sum(f.total_bytes for f in flows)
        total_packets = sum(f.total_packets for f in flows)

        # Show selection status
        if self._selected_flows:
            title = f"[bold]Overview[/bold] [yellow](Selected: {len(flows)})[/yellow]"
        else:
            title = "[bold]Overview[/bold]"

        lines = [
            f"[cyan]Flows:[/cyan] [white]{len(flows)}[/white]",
            f"[cyan]Total Bytes:[/cyan] [white]{format_bytes(total_bytes)}[/white]",
            f"[cyan]Total Packets:[/cyan] [white]{format_packets(total_packets)}[/white]",
        ]

        if self.geo_resolver and not self._selected_flows:
            cache_stats = self.geo_resolver.get_cache_stats()
            lines.append("")
            lines.append(f"[cyan]Geo Cache:[/cyan] [white]{cache_stats['size']}/{cache_stats['max_size']}[/white]")

        return Panel("\n".join(lines), title=title, border_style="blue")

    def _render_protocol_table(self) -> Panel:
        """Render protocol statistics."""
        proto_stats = self._get_protocol_stats()

        if not proto_stats:
            return Panel("No data", title="[bold]By Protocol[/bold]", border_style="blue")

        table = Table(show_header=True, header_style="bold", box=None, expand=True)
        table.add_column("Protocol", style="magenta")
        table.add_column("Flows", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("Packets", justify="right")

        # Sort by bytes
        sorted_proto = sorted(proto_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)

        for proto, stats in sorted_proto:
            table.add_row(
                proto,
                str(stats["flows"]),
                format_bytes(stats["bytes"]),
                format_packets(stats["packets"]),
            )

        return Panel(table, title="[bold]By Protocol[/bold]", border_style="blue")

    def _render_country_chart(self) -> Panel:
        """Render country distribution."""
        country_stats = self._get_country_stats()

        if not country_stats:
            return Panel("No geo data", title="[bold]By Country[/bold]", border_style="blue")

        sorted_countries = sorted(country_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        max_count = sorted_countries[0][1] if sorted_countries else 1

        lines = []
        for country, count in sorted_countries:
            bar_len = int(15 * count / max_count)
            bar = "█" * bar_len
            lines.append(f"[cyan]{country:20}[/cyan] [green]{bar}[/green] {count}")

        return Panel("\n".join(lines) if lines else "No data", title="[bold]By Country[/bold]", border_style="blue")

    def _render_isp_chart(self) -> Panel:
        """Render ISP distribution."""
        isp_stats = self._get_isp_stats()

        if not isp_stats:
            return Panel("No ISP data", title="[bold]By ISP[/bold]", border_style="blue")

        sorted_isps = sorted(isp_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        max_count = sorted_isps[0][1] if sorted_isps else 1

        lines = []
        for isp, count in sorted_isps:
            isp_display = isp[:22] + "..." if len(isp) > 25 else isp
            bar_len = int(12 * count / max_count)
            bar = "█" * bar_len
            lines.append(f"[yellow]{isp_display:25}[/yellow] [green]{bar}[/green] {count}")

        return Panel("\n".join(lines) if lines else "No data", title="[bold]By ISP[/bold]", border_style="blue")

    def _get_hostname(self, ip: str) -> str:
        """Get hostname for an IP."""
        if not self.dns_resolver:
            return ""
        info = self.dns_resolver.get_cached(ip)
        if info and info.domain:
            return info.domain
        if info and info.hostname:
            return info.hostname[:25] if len(info.hostname) > 25 else info.hostname
        return ""

    def _render_top_talkers(self) -> Panel:
        """Render top talkers by traffic."""
        flows = self._get_flows()
        # Sort by bytes and take top 5
        top_flows = sorted(flows, key=lambda f: f.total_bytes, reverse=True)[:5]

        if not top_flows:
            return Panel("No data", title="[bold]Top Talkers[/bold]", border_style="blue")

        lines = []
        for flow in top_flows:
            hostname = self._get_hostname(flow.dst_ip)
            if hostname:
                display = f"{hostname} ({flow.dst_ip})"
                if len(display) > 40:
                    display = hostname[:35] + "..."
            else:
                display = f"{flow.dst_ip}:{flow.dst_port}" if flow.dst_port else flow.dst_ip
            lines.append(f"[green]{display:40}[/green] [white]{format_bytes(flow.total_bytes):>10}[/white]")

        return Panel("\n".join(lines), title="[bold]Top Talkers[/bold]", border_style="blue")

    def _render_top_domains(self) -> Panel:
        """Render top domains by flow count."""
        if not self.dns_resolver:
            return Panel("DNS resolver not available", title="[bold]Top Domains[/bold]", border_style="blue")

        domain_stats = defaultdict(lambda: {"flows": 0, "bytes": 0})
        for flow in self._get_flows():
            hostname = self._get_hostname(flow.dst_ip)
            if hostname:
                domain_stats[hostname]["flows"] += 1
                domain_stats[hostname]["bytes"] += flow.total_bytes

        if not domain_stats:
            return Panel("No DNS data yet", title="[bold]Top Domains[/bold]", border_style="blue")

        sorted_domains = sorted(domain_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)[:8]

        lines = []
        for domain, stats in sorted_domains:
            domain_display = domain[:28] if len(domain) > 28 else domain
            lines.append(f"[cyan]{domain_display:28}[/cyan] [white]{format_bytes(stats['bytes']):>10}[/white] ({stats['flows']} flows)")

        return Panel("\n".join(lines), title="[bold]Top Domains[/bold]", border_style="blue")

    def _render_dns_stats(self) -> Panel:
        """Render DNS query statistics."""
        if not self.dns_tracker:
            return Panel("[dim]DNS tracker not available[/dim]", title="[bold]DNS Stats[/bold]", border_style="blue")

        stats = self.dns_tracker.get_summary_stats()
        total_queries = stats.get("total_queries", 0)
        total_responses = stats.get("total_responses", 0)
        nxdomain_count = stats.get("nxdomain_count", 0)
        error_count = stats.get("error_count", 0)

        if total_queries == 0:
            return Panel("[dim]No DNS traffic yet[/dim]", title="[bold]DNS Stats[/bold]", border_style="blue")

        # Response and error rates
        response_rate = (total_responses / total_queries * 100) if total_queries > 0 else 0
        nxdomain_rate = (nxdomain_count / max(1, total_responses) * 100)
        error_rate = (error_count / max(1, total_responses) * 100)

        # Color based on rates
        nxdomain_style = "red" if nxdomain_rate > 10 else "yellow" if nxdomain_rate > 5 else "green"
        error_style = "red" if error_rate > 5 else "yellow" if error_rate > 2 else "green"

        lines = [
            f"[cyan]Queries:[/cyan]        {total_queries:>8}",
            f"[cyan]Responses:[/cyan]      {total_responses:>8}",
            f"[cyan]Response Rate:[/cyan] {response_rate:>7.1f}%",
            f"[{nxdomain_style}]NXDOMAIN:[/{nxdomain_style}]       {nxdomain_count:>8} ({nxdomain_rate:.1f}%)",
            f"[{error_style}]Errors:[/{error_style}]         {error_count:>8} ({error_rate:.1f}%)",
        ]

        # Top query types
        type_breakdown = self.dns_tracker.get_query_type_breakdown()
        if type_breakdown:
            lines.append("")
            lines.append("[bold]Query Types:[/bold]")
            for item in type_breakdown[:5]:
                qtype = item.get("query_type_name", "?")
                count = item.get("count", 0)
                lines.append(f"  [magenta]{qtype:6}[/magenta] {count:>6}")

        return Panel("\n".join(lines), title="[bold]DNS Stats[/bold]", border_style="blue")

    def render(self) -> RenderableType:
        """Render the stats panel."""
        # Top row: overview and protocol
        top_row = Columns([
            self._render_overview(),
            self._render_protocol_table(),
        ], expand=True)

        # Middle row: country and ISP
        middle_row = Columns([
            self._render_country_chart(),
            self._render_isp_chart(),
        ], expand=True)

        # Bottom row: top talkers and DNS stats
        bottom_row = Columns([
            self._render_top_talkers(),
            self._render_dns_stats(),
        ], expand=True)

        return Group(top_row, middle_row, bottom_row)
