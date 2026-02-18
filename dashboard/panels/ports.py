"""Port transit tracking panel."""

from typing import List, Optional, Dict
from collections import defaultdict
from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.text import Text
from rich.columns import Columns

from tracking.ports import PortTracker, PortStats, KNOWN_SERVICES
from tracking.flow import Flow
from utils.network import format_bytes, format_packets


class PortsPanel:
    """Panel displaying port transit statistics."""

    def __init__(self, port_tracker: PortTracker):
        self.port_tracker = port_tracker
        self.sort_by = "bytes"  # bytes, packets, connections, rate
        self.show_count = 25
        self._selected_flows: Optional[List[Flow]] = None

    def set_selected_flows(self, flows: Optional[List[Flow]]) -> None:
        """Set selected flows to filter port stats."""
        self._selected_flows = flows if flows else None

    def _get_port_stats_from_flows(self) -> List[PortStats]:
        """Calculate port stats from selected flows."""
        if not self._selected_flows:
            return []

        port_data: Dict[int, Dict] = defaultdict(lambda: {
            "bytes_in": 0, "bytes_out": 0, "packets": 0,
            "protocol": "TCP", "sources": set(), "destinations": set()
        })

        for flow in self._selected_flows:
            # Track destination port (more meaningful)
            if flow.dst_port:
                port = flow.dst_port
                port_data[port]["bytes_out"] += flow.bytes_sent
                port_data[port]["bytes_in"] += flow.bytes_recv
                port_data[port]["packets"] += flow.total_packets
                port_data[port]["protocol"] = flow.protocol_name
                port_data[port]["sources"].add(flow.src_ip)
                port_data[port]["destinations"].add(flow.dst_ip)

            # Also track source port for server responses
            if flow.src_port and flow.src_port != flow.dst_port:
                port = flow.src_port
                port_data[port]["bytes_in"] += flow.bytes_sent
                port_data[port]["bytes_out"] += flow.bytes_recv
                port_data[port]["packets"] += flow.total_packets
                port_data[port]["protocol"] = flow.protocol_name

        # Convert to PortStats
        result = []
        for port, data in port_data.items():
            stats = PortStats(
                port=port,
                protocol=data["protocol"],
                bytes_in=data["bytes_in"],
                bytes_out=data["bytes_out"],
                packets_in=data["packets"] // 2,
                packets_out=data["packets"] // 2,
            )
            # Populate the underlying sets (unique_sources/unique_destinations are computed properties)
            stats.src_ips = data.get("sources", set())
            stats.dst_ips = data.get("destinations", set())
            stats.hit_count = len(stats.src_ips)
            result.append(stats)

        # Sort
        if self.sort_by == "bytes":
            result.sort(key=lambda x: x.total_bytes, reverse=True)
        elif self.sort_by == "packets":
            result.sort(key=lambda x: x.total_packets, reverse=True)
        else:
            result.sort(key=lambda x: x.total_bytes, reverse=True)

        return result[:self.show_count]

    def cycle_sort(self) -> str:
        """Cycle through sort modes."""
        modes = ["bytes", "packets", "connections", "rate"]
        idx = modes.index(self.sort_by)
        self.sort_by = modes[(idx + 1) % len(modes)]
        return self.sort_by

    def _render_top_ports(self) -> Table:
        """Render top ports table."""
        if self._selected_flows:
            ports = self._get_port_stats_from_flows()
            title = f"[bold]Ports for Selected Flows[/bold] [yellow]({len(self._selected_flows)} flows)[/yellow]"
        else:
            ports = self.port_tracker.get_top_ports(self.show_count, by=self.sort_by)
            title = f"[bold]Top Ports by {self.sort_by.title()}[/bold]"

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title=title,
        )

        table.add_column("Port", style="cyan", justify="right", width=6)
        table.add_column("Proto", style="magenta", width=5)
        table.add_column("Service", style="yellow", width=12)
        table.add_column("Hits", justify="right", width=6)
        table.add_column("↓ In", justify="right", width=9)
        table.add_column("↑ Out", justify="right", width=9)
        table.add_column("Pkts", justify="right", width=7)
        table.add_column("Srcs", justify="right", width=5)
        table.add_column("Dsts", justify="right", width=5)
        table.add_column("Rate", justify="right", width=8)

        for stats in ports:
            service_name, _ = KNOWN_SERVICES.get(stats.port, ("", ""))

            # Color based on port type
            if stats.port < 1024:
                port_style = "bold cyan"
            elif stats.port < 49152:
                port_style = "cyan"
            else:
                port_style = "dim cyan"

            rate = f"{stats.packets_per_second:.1f}/s"

            # Color hit count based on value
            hit_str = str(stats.hit_count)
            if stats.hit_count > 50:
                hit_style = "bold red"
            elif stats.hit_count > 20:
                hit_style = "yellow"
            else:
                hit_style = "dim"

            table.add_row(
                Text(str(stats.port), style=port_style),
                stats.protocol,
                service_name or "-",
                Text(hit_str, style=hit_style),
                format_bytes(stats.bytes_in),
                format_bytes(stats.bytes_out),
                format_packets(stats.total_packets),
                str(stats.unique_sources),
                str(stats.unique_destinations),
                rate,
                style=None,
            )

        return table

    def _render_port_categories(self) -> Panel:
        """Render traffic by port category."""
        ports = self.port_tracker.get_top_ports(100, by="bytes")

        # Categorize ports
        categories = {
            "Well-Known (0-1023)": {"bytes": 0, "packets": 0, "count": 0},
            "Registered (1024-49151)": {"bytes": 0, "packets": 0, "count": 0},
            "Dynamic (49152+)": {"bytes": 0, "packets": 0, "count": 0},
        }

        for stats in ports:
            if stats.port < 1024:
                cat = "Well-Known (0-1023)"
            elif stats.port < 49152:
                cat = "Registered (1024-49151)"
            else:
                cat = "Dynamic (49152+)"

            categories[cat]["bytes"] += stats.total_bytes
            categories[cat]["packets"] += stats.total_packets
            categories[cat]["count"] += 1

        total_bytes = sum(c["bytes"] for c in categories.values())

        lines = []
        for name, data in categories.items():
            pct = (data["bytes"] / max(1, total_bytes)) * 100
            bar_len = int(pct / 5)
            bar = "█" * bar_len

            lines.append(
                f"[cyan]{name:24}[/cyan] [green]{bar:20}[/green] "
                f"{format_bytes(data['bytes']):>10} ({pct:5.1f}%)"
            )

        return Panel(
            "\n".join(lines),
            title="[bold]Traffic by Port Range[/bold]",
            border_style="blue",
        )

    def _render_scan_detection(self) -> Panel:
        """Render port scan detection panel."""
        if self._selected_flows:
            return Panel(
                "[dim]Scan detection not available for selected flows[/dim]",
                title="[bold]Port Scan Detection[/bold]",
                border_style="red",
            )

        # Get scan activity
        activities = self.port_tracker.get_scan_activity(min_ports=5)
        likely_scanners = self.port_tracker.get_likely_scanners()

        lines = []

        # Show likely scanners first
        if likely_scanners:
            lines.append("[bold red]⚠ Likely Port Scanners:[/bold red]")
            for activity in likely_scanners[:3]:
                ports_str = ", ".join(str(p) for p in sorted(activity.ports_hit)[:10])
                if len(activity.ports_hit) > 10:
                    ports_str += f" +{len(activity.ports_hit)-10} more"
                lines.append(
                    f"  [red]{activity.src_ip}[/red] → {activity.unique_ports} ports "
                    f"[dim]({activity.scan_rate:.1f} ports/s)[/dim]"
                )
            lines.append("")

        # Show suspicious activity
        other_activity = [a for a in activities if not a.is_likely_scan][:5]
        if other_activity:
            lines.append("[yellow]Suspicious Activity (5+ ports):[/yellow]")
            for activity in other_activity:
                lines.append(
                    f"  [cyan]{activity.src_ip}[/cyan] → {activity.unique_ports} ports "
                    f"[dim]({activity.packet_count} pkts)[/dim]"
                )
        elif not likely_scanners:
            lines.append("[green]No scan activity detected[/green]")

        return Panel(
            "\n".join(lines) if lines else "No data",
            title="[bold]Port Scan Detection[/bold]",
            border_style="red" if likely_scanners else "blue",
        )

    def _render_top_hit_ports(self) -> Panel:
        """Render top hit ports panel."""
        if self._selected_flows:
            # Calculate from selected flows
            hit_counts: Dict[int, int] = defaultdict(int)
            for flow in self._selected_flows:
                if flow.dst_port:
                    hit_counts[flow.dst_port] += 1

            lines = []
            sorted_ports = sorted(hit_counts.items(), key=lambda x: x[1], reverse=True)[:8]
            if sorted_ports:
                max_hits = sorted_ports[0][1]
                for port, hits in sorted_ports:
                    service_name, _ = KNOWN_SERVICES.get(port, ("", ""))
                    bar_len = int(12 * hits / max(1, max_hits))
                    bar = "█" * bar_len
                    label = f"{port} ({service_name})" if service_name else str(port)
                    lines.append(f"[cyan]{label:18}[/cyan] [green]{bar:12}[/green] {hits} hits")
            else:
                lines.append("[dim]No port data[/dim]")
        else:
            top_ports = self.port_tracker.get_top_hit_ports(8)
            lines = []
            if top_ports:
                max_hits = top_ports[0].hit_count if top_ports else 1
                for stats in top_ports:
                    if stats.hit_count == 0:
                        continue
                    service_name, _ = KNOWN_SERVICES.get(stats.port, ("", ""))
                    bar_len = int(12 * stats.hit_count / max(1, max_hits))
                    bar = "█" * bar_len
                    label = f"{stats.port} ({service_name})" if service_name else str(stats.port)
                    lines.append(f"[cyan]{label:18}[/cyan] [green]{bar:12}[/green] {stats.hit_count} hits")

        return Panel(
            "\n".join(lines) if lines else "[dim]No hit data yet[/dim]",
            title="[bold]Top Hit Ports[/bold]",
            border_style="blue",
        )

    def _render_service_breakdown(self) -> Panel:
        """Render traffic by service type."""
        ports = self.port_tracker.get_top_ports(100, by="bytes")

        # Group by service
        services = {}
        for stats in ports:
            service_name, _ = KNOWN_SERVICES.get(stats.port, ("Other", ""))
            if service_name not in services:
                services[service_name] = {"bytes": 0, "packets": 0, "ports": []}
            services[service_name]["bytes"] += stats.total_bytes
            services[service_name]["packets"] += stats.total_packets
            services[service_name]["ports"].append(stats.port)

        # Sort by bytes
        sorted_services = sorted(services.items(), key=lambda x: x[1]["bytes"], reverse=True)

        lines = []
        total_bytes = sum(s[1]["bytes"] for s in sorted_services)

        for name, data in sorted_services[:12]:
            pct = (data["bytes"] / max(1, total_bytes)) * 100
            bar_len = int(pct / 8)
            bar = "█" * bar_len

            lines.append(
                f"[yellow]{name:12}[/yellow] [green]{bar:12}[/green] "
                f"{format_bytes(data['bytes']):>10} ({pct:4.1f}%)"
            )

        return Panel(
            "\n".join(lines) if lines else "No data",
            title="[bold]Traffic by Service[/bold]",
            border_style="blue",
        )

    def _render_summary(self) -> Text:
        """Render summary line."""
        summary = self.port_tracker.get_summary()
        active = len(self.port_tracker.get_active_ports(60))
        likely_scanners = self.port_tracker.get_likely_scanners()

        scan_status = (
            f"[bold red]⚠ {len(likely_scanners)} scanner(s)[/bold red]"
            if likely_scanners else "[green]No scans[/green]"
        )

        return Text.from_markup(
            f"[dim]Tracked ports: {summary['total_ports']} | "
            f"Active (60s): {active} | "
            f"Total: {format_bytes(summary['total_bytes'])} | "
            f"Scans: {scan_status}[/dim] | "
            f"[dim]Sort: {self.sort_by} (press 's' to change)[/dim]"
        )

    def render(self) -> RenderableType:
        """Render the ports panel."""
        # Main table
        top_table = self._render_top_ports()

        # Middle row: Port categories and service breakdown
        middle_panels = Columns([
            self._render_port_categories(),
            self._render_service_breakdown(),
        ], expand=True)

        # Bottom row: Scan detection and hit counts
        bottom_panels = Columns([
            self._render_scan_detection(),
            self._render_top_hit_ports(),
        ], expand=True)

        # Summary
        summary = self._render_summary()

        return Group(top_table, middle_panels, bottom_panels, summary)
