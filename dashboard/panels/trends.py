"""Traffic trends panel with time-series visualizations."""

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Optional, TYPE_CHECKING

from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.columns import Columns
from rich.text import Text

from dashboard.graphs import sparkline, traffic_distribution, _format_number

if TYPE_CHECKING:
    from tracking.flow import FlowTracker
    from tracking.dns_tracker import DNSTracker
    from tracking.tcp_state import TCPStateTracker


@dataclass
class TrendData:
    """Rolling time-series data storage."""

    max_points: int = 60  # 60 seconds of data

    # Bandwidth
    bytes_in: Deque[float] = field(default_factory=lambda: deque(maxlen=60))
    bytes_out: Deque[float] = field(default_factory=lambda: deque(maxlen=60))

    # Packets
    packets_in: Deque[float] = field(default_factory=lambda: deque(maxlen=60))
    packets_out: Deque[float] = field(default_factory=lambda: deque(maxlen=60))

    # Connections
    new_connections: Deque[int] = field(default_factory=lambda: deque(maxlen=60))
    active_connections: Deque[int] = field(default_factory=lambda: deque(maxlen=60))

    # DNS
    dns_queries: Deque[int] = field(default_factory=lambda: deque(maxlen=60))
    dns_errors: Deque[int] = field(default_factory=lambda: deque(maxlen=60))

    # TCP
    tcp_retransmissions: Deque[int] = field(default_factory=lambda: deque(maxlen=60))
    tcp_resets: Deque[int] = field(default_factory=lambda: deque(maxlen=60))

    # Tracking
    last_update: float = 0.0
    _prev_bytes_in: int = 0
    _prev_bytes_out: int = 0
    _prev_packets_in: int = 0
    _prev_packets_out: int = 0
    _prev_dns_queries: int = 0
    _prev_dns_errors: int = 0
    _prev_tcp_retrans: int = 0
    _prev_tcp_resets: int = 0
    _prev_connections: int = 0


class TrendsPanel:
    """Panel displaying traffic trends over time."""

    def __init__(
        self,
        flow_tracker: "FlowTracker",
        dns_tracker: Optional["DNSTracker"] = None,
        tcp_tracker: Optional["TCPStateTracker"] = None,
        update_interval: float = 1.0,
    ):
        self.flow_tracker = flow_tracker
        self.dns_tracker = dns_tracker
        self.tcp_tracker = tcp_tracker
        self.update_interval = update_interval
        self.data = TrendData()

    def update(self) -> None:
        """Update trend data with current values."""
        now = time.time()

        # Only update once per interval
        if now - self.data.last_update < self.update_interval:
            return

        self.data.last_update = now

        # Get current totals from flow tracker
        flows = self.flow_tracker.get_flows()
        total_bytes_in = sum(f.bytes_recv for f in flows)
        total_bytes_out = sum(f.bytes_sent for f in flows)
        total_packets_in = sum(f.packets_recv for f in flows)
        total_packets_out = sum(f.packets_sent for f in flows)
        total_connections = len(flows)

        # Calculate deltas (per-second rates)
        bytes_in_delta = total_bytes_in - self.data._prev_bytes_in
        bytes_out_delta = total_bytes_out - self.data._prev_bytes_out
        packets_in_delta = total_packets_in - self.data._prev_packets_in
        packets_out_delta = total_packets_out - self.data._prev_packets_out
        new_conn_delta = max(0, total_connections - self.data._prev_connections)

        # Store rates
        self.data.bytes_in.append(max(0, bytes_in_delta))
        self.data.bytes_out.append(max(0, bytes_out_delta))
        self.data.packets_in.append(max(0, packets_in_delta))
        self.data.packets_out.append(max(0, packets_out_delta))
        self.data.new_connections.append(new_conn_delta)
        self.data.active_connections.append(
            sum(1 for f in flows if f.is_active)
        )

        # Update previous values
        self.data._prev_bytes_in = total_bytes_in
        self.data._prev_bytes_out = total_bytes_out
        self.data._prev_packets_in = total_packets_in
        self.data._prev_packets_out = total_packets_out
        self.data._prev_connections = total_connections

        # DNS stats
        if self.dns_tracker:
            stats = self.dns_tracker.get_summary_stats()
            total_queries = stats.get("total_queries", 0)
            total_errors = stats.get("error_count", 0)

            queries_delta = total_queries - self.data._prev_dns_queries
            errors_delta = total_errors - self.data._prev_dns_errors

            self.data.dns_queries.append(max(0, queries_delta))
            self.data.dns_errors.append(max(0, errors_delta))

            self.data._prev_dns_queries = total_queries
            self.data._prev_dns_errors = total_errors

        # TCP stats
        if self.tcp_tracker:
            stats = self.tcp_tracker.get_stats()
            total_retrans = stats["retransmission_stats"]["total_retransmissions"]
            total_resets = stats["total_resets"]

            retrans_delta = total_retrans - self.data._prev_tcp_retrans
            resets_delta = total_resets - self.data._prev_tcp_resets

            self.data.tcp_retransmissions.append(max(0, retrans_delta))
            self.data.tcp_resets.append(max(0, resets_delta))

            self.data._prev_tcp_retrans = total_retrans
            self.data._prev_tcp_resets = total_resets

    def _render_bandwidth(self) -> Panel:
        """Render bandwidth over time."""
        bytes_in = list(self.data.bytes_in)
        bytes_out = list(self.data.bytes_out)

        if not bytes_in:
            return Panel(
                "[dim]No data yet[/dim]",
                title="[bold]Bandwidth[/bold]",
                border_style="green",
            )

        # Current rates
        current_in = bytes_in[-1] if bytes_in else 0
        current_out = bytes_out[-1] if bytes_out else 0
        max_in = max(bytes_in) if bytes_in else 0
        max_out = max(bytes_out) if bytes_out else 0

        lines = []

        # Inbound
        lines.append(f"[green]↓ In:[/green]  {_format_number(current_in)}/s (max: {_format_number(max_in)}/s)")
        spark_in = sparkline(bytes_in, width=50, style="green")
        lines.append(spark_in.plain)

        lines.append("")

        # Outbound
        lines.append(f"[cyan]↑ Out:[/cyan] {_format_number(current_out)}/s (max: {_format_number(max_out)}/s)")
        spark_out = sparkline(bytes_out, width=50, style="cyan")
        lines.append(spark_out.plain)

        # Distribution bar
        total_in = sum(bytes_in)
        total_out = sum(bytes_out)
        if total_in + total_out > 0:
            lines.append("")
            lines.append(traffic_distribution(total_in, total_out, width=50))

        return Panel(
            "\n".join(lines),
            title="[bold]Bandwidth (last 60s)[/bold]",
            border_style="green",
        )

    def _render_packets(self) -> Panel:
        """Render packets per second over time."""
        packets_in = list(self.data.packets_in)
        packets_out = list(self.data.packets_out)

        if not packets_in:
            return Panel(
                "[dim]No data yet[/dim]",
                title="[bold]Packets[/bold]",
                border_style="blue",
            )

        current_in = packets_in[-1] if packets_in else 0
        current_out = packets_out[-1] if packets_out else 0

        lines = []
        lines.append(f"[green]↓ In:[/green]  {current_in:.0f}/s")
        spark_in = sparkline(packets_in, width=50, style="green")
        lines.append(spark_in.plain)

        lines.append("")
        lines.append(f"[cyan]↑ Out:[/cyan] {current_out:.0f}/s")
        spark_out = sparkline(packets_out, width=50, style="cyan")
        lines.append(spark_out.plain)

        return Panel(
            "\n".join(lines),
            title="[bold]Packets/sec (last 60s)[/bold]",
            border_style="blue",
        )

    def _render_connections(self) -> Panel:
        """Render connection trends."""
        new_conns = list(self.data.new_connections)
        active_conns = list(self.data.active_connections)

        if not new_conns:
            return Panel(
                "[dim]No data yet[/dim]",
                title="[bold]Connections[/bold]",
                border_style="yellow",
            )

        current_active = active_conns[-1] if active_conns else 0
        total_new = sum(new_conns)

        lines = []
        lines.append(f"[yellow]Active:[/yellow] {current_active}")
        spark_active = sparkline(active_conns, width=50, style="yellow")
        lines.append(spark_active.plain)

        lines.append("")
        lines.append(f"[cyan]New (last 60s):[/cyan] {total_new}")
        spark_new = sparkline(new_conns, width=50, style="cyan")
        lines.append(spark_new.plain)

        return Panel(
            "\n".join(lines),
            title="[bold]Connections[/bold]",
            border_style="yellow",
        )

    def _render_dns(self) -> Panel:
        """Render DNS query trends."""
        if not self.dns_tracker:
            return Panel(
                "[dim]DNS tracker not available[/dim]",
                title="[bold]DNS Queries[/bold]",
                border_style="magenta",
            )

        queries = list(self.data.dns_queries)
        errors = list(self.data.dns_errors)

        if not queries:
            return Panel(
                "[dim]No DNS data yet[/dim]",
                title="[bold]DNS Queries[/bold]",
                border_style="magenta",
            )

        total_queries = sum(queries)
        total_errors = sum(errors)
        current_rate = queries[-1] if queries else 0

        lines = []
        lines.append(f"[magenta]Queries/sec:[/magenta] {current_rate}")
        spark_queries = sparkline(queries, width=50, style="magenta")
        lines.append(spark_queries.plain)

        lines.append("")
        lines.append(f"[dim]Total (60s): {total_queries} queries, {total_errors} errors[/dim]")

        if total_errors > 0:
            spark_errors = sparkline(errors, width=50, style="red")
            lines.append("[red]Errors:[/red]")
            lines.append(spark_errors.plain)

        return Panel(
            "\n".join(lines),
            title="[bold]DNS Queries (last 60s)[/bold]",
            border_style="magenta",
        )

    def _render_tcp_health(self) -> Panel:
        """Render TCP health indicators."""
        if not self.tcp_tracker:
            return Panel(
                "[dim]TCP tracker not available[/dim]",
                title="[bold]TCP Health[/bold]",
                border_style="red",
            )

        retrans = list(self.data.tcp_retransmissions)
        resets = list(self.data.tcp_resets)

        if not retrans:
            return Panel(
                "[dim]No TCP data yet[/dim]",
                title="[bold]TCP Health[/bold]",
                border_style="red",
            )

        total_retrans = sum(retrans)
        total_resets = sum(resets)

        # Determine health status
        if total_retrans == 0 and total_resets == 0:
            status = "[green]● Healthy[/green]"
        elif total_retrans < 10 and total_resets < 5:
            status = "[yellow]● Minor Issues[/yellow]"
        else:
            status = "[red]● Problems Detected[/red]"

        lines = [status, ""]

        lines.append(f"[yellow]Retransmissions (60s):[/yellow] {total_retrans}")
        if retrans:
            spark_retrans = sparkline(retrans, width=50, style="yellow")
            lines.append(spark_retrans.plain)

        lines.append("")
        lines.append(f"[red]Resets (60s):[/red] {total_resets}")
        if resets:
            spark_resets = sparkline(resets, width=50, style="red")
            lines.append(spark_resets.plain)

        return Panel(
            "\n".join(lines),
            title="[bold]TCP Health[/bold]",
            border_style="red",
        )

    def _render_summary(self) -> Text:
        """Render summary line."""
        bytes_in = list(self.data.bytes_in)
        bytes_out = list(self.data.bytes_out)

        if not bytes_in:
            return Text.from_markup("[dim]Collecting data...[/dim]")

        current_in = bytes_in[-1] if bytes_in else 0
        current_out = bytes_out[-1] if bytes_out else 0
        data_points = len(bytes_in)

        return Text.from_markup(
            f"[dim]Current: ↓{_format_number(current_in)}/s ↑{_format_number(current_out)}/s | "
            f"Data points: {data_points}/60[/dim]"
        )

    def render(self) -> RenderableType:
        """Render the trends panel."""
        # Update data
        self.update()

        # Top row: bandwidth and packets
        top_row = Columns([
            self._render_bandwidth(),
            self._render_packets(),
        ], expand=True)

        # Middle row: connections and DNS
        middle_row = Columns([
            self._render_connections(),
            self._render_dns(),
        ], expand=True)

        # Bottom: TCP health and summary
        bottom_row = Columns([
            self._render_tcp_health(),
        ], expand=True)

        summary = self._render_summary()

        return Group(top_row, middle_row, bottom_row, summary)
