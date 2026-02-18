"""TCP connection analysis panel."""

from typing import List
from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.columns import Columns
from rich.text import Text

from tracking.tcp_state import TCPStateTracker, TCPConnection, TCPState
from utils.network import format_bytes


class TCPPanel:
    """Panel displaying TCP connection states and statistics."""

    def __init__(self, tcp_tracker: TCPStateTracker):
        self.tcp_tracker = tcp_tracker
        self.show_count = 15
        self.sort_by = "bytes"  # bytes, rtt, retrans, recent

    def cycle_sort(self) -> str:
        """Cycle through sort modes."""
        modes = ["bytes", "rtt", "retrans", "recent"]
        idx = modes.index(self.sort_by)
        self.sort_by = modes[(idx + 1) % len(modes)]
        return self.sort_by

    def _get_sorted_connections(self) -> List[TCPConnection]:
        """Get connections sorted by current mode."""
        conns = self.tcp_tracker.get_connections()

        if self.sort_by == "bytes":
            conns.sort(key=lambda c: c.total_bytes, reverse=True)
        elif self.sort_by == "rtt":
            conns.sort(key=lambda c: c.avg_rtt or 0, reverse=True)
        elif self.sort_by == "retrans":
            conns.sort(key=lambda c: c.retransmissions, reverse=True)
        elif self.sort_by == "recent":
            conns.sort(key=lambda c: c.last_seen, reverse=True)

        return conns[:self.show_count]

    def _state_style(self, state: TCPState) -> str:
        """Get style for connection state."""
        styles = {
            TCPState.CLOSED: "dim",
            TCPState.SYN_SENT: "yellow",
            TCPState.SYN_RECEIVED: "yellow",
            TCPState.ESTABLISHED: "green",
            TCPState.FIN_WAIT_1: "cyan",
            TCPState.FIN_WAIT_2: "cyan",
            TCPState.CLOSE_WAIT: "magenta",
            TCPState.CLOSING: "magenta",
            TCPState.LAST_ACK: "magenta",
            TCPState.TIME_WAIT: "dim cyan",
            TCPState.LISTEN: "blue",
        }
        return styles.get(state, "white")

    def _render_connections_table(self) -> Table:
        """Render TCP connections table."""
        connections = self._get_sorted_connections()

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title=f"[bold]TCP Connections (by {self.sort_by})[/bold]",
        )

        table.add_column("Source", style="cyan", width=22)
        table.add_column("Destination", style="cyan", width=22)
        table.add_column("State", width=12)
        table.add_column("Bytes", justify="right", width=10)
        table.add_column("Pkts", justify="right", width=7)
        table.add_column("RTT", justify="right", width=8)
        table.add_column("Retx", justify="right", width=5)
        table.add_column("Duration", justify="right", width=8)

        for conn in connections:
            src = f"{conn.src_ip}:{conn.src_port}"
            dst = f"{conn.dst_ip}:{conn.dst_port}"

            # Format RTT
            if conn.avg_rtt:
                rtt_str = f"{conn.avg_rtt:.1f}ms"
                if conn.avg_rtt > 200:
                    rtt_style = "bold red"
                elif conn.avg_rtt > 100:
                    rtt_style = "yellow"
                else:
                    rtt_style = "green"
            else:
                rtt_str = "-"
                rtt_style = "dim"

            # Format retransmissions
            retx = str(conn.retransmissions)
            if conn.retransmissions > 10:
                retx_style = "bold red"
            elif conn.retransmissions > 0:
                retx_style = "yellow"
            else:
                retx_style = "dim"

            # Format duration
            duration = conn.duration
            if duration < 60:
                dur_str = f"{duration:.1f}s"
            elif duration < 3600:
                dur_str = f"{duration/60:.1f}m"
            else:
                dur_str = f"{duration/3600:.1f}h"

            table.add_row(
                src[:22],
                dst[:22],
                Text(conn.state.name, style=self._state_style(conn.state)),
                format_bytes(conn.total_bytes),
                str(conn.total_packets),
                Text(rtt_str, style=rtt_style),
                Text(retx, style=retx_style),
                dur_str,
            )

        return table

    def _render_state_summary(self) -> Panel:
        """Render connection state summary."""
        summary = self.tcp_tracker.get_state_summary()

        lines = []
        for state in TCPState:
            count = summary.get(state.name, 0)
            if count > 0:
                style = self._state_style(state)
                bar_len = min(20, count)
                bar = "█" * bar_len
                lines.append(f"[{style}]{state.name:12}[/{style}] [{style}]{bar}[/{style}] {count}")

        return Panel(
            "\n".join(lines) if lines else "[dim]No TCP connections[/dim]",
            title="[bold]Connection States[/bold]",
            border_style="blue",
        )

    def _render_stats(self) -> Panel:
        """Render TCP statistics."""
        stats = self.tcp_tracker.get_stats()
        retrans = stats["retransmission_stats"]

        lines = [
            f"[cyan]Total Connections:[/cyan]  {stats['total_connections']}",
            f"[yellow]SYN Packets:[/yellow]        {stats['total_syns']}",
            f"[green]Established:[/green]         {stats['total_established']}",
            f"[magenta]FIN Packets:[/magenta]         {stats['total_fins']}",
            f"[red]RST Packets:[/red]         {stats['total_resets']}",
            "",
            f"[yellow]Retransmissions:[/yellow]     {retrans['total_retransmissions']}",
            f"[yellow]Conns w/ Retrans:[/yellow]    {retrans['connections_with_retransmissions']}",
        ]

        # Calculate retransmission rate
        total_conns = retrans['total_connections']
        if total_conns > 0:
            retrans_pct = (retrans['connections_with_retransmissions'] / total_conns) * 100
            lines.append(f"[yellow]Retrans Rate:[/yellow]        {retrans_pct:.1f}%")

        return Panel(
            "\n".join(lines),
            title="[bold]TCP Statistics[/bold]",
            border_style="blue",
        )

    def _render_rtt_summary(self) -> Panel:
        """Render RTT statistics."""
        top_rtt = self.tcp_tracker.get_top_by_rtt(5)

        lines = []
        if top_rtt:
            lines.append("[bold]Highest RTT Connections:[/bold]")
            lines.append("")
            for conn in top_rtt:
                rtt = conn.avg_rtt or 0
                if rtt > 200:
                    style = "red"
                elif rtt > 100:
                    style = "yellow"
                else:
                    style = "green"

                lines.append(
                    f"[{style}]{rtt:6.1f}ms[/{style}] "
                    f"[dim]{conn.src_ip}:{conn.src_port} → {conn.dst_ip}:{conn.dst_port}[/dim]"
                )
        else:
            lines.append("[dim]No RTT data yet[/dim]")

        return Panel(
            "\n".join(lines),
            title="[bold]RTT Analysis[/bold]",
            border_style="yellow",
        )

    def _render_retrans_summary(self) -> Panel:
        """Render retransmission statistics."""
        conns = self.tcp_tracker.get_connections()
        retrans_conns = [c for c in conns if c.retransmissions > 0]
        retrans_conns.sort(key=lambda c: c.retransmissions, reverse=True)

        lines = []
        if retrans_conns:
            lines.append("[bold]Connections with Retransmissions:[/bold]")
            lines.append("")
            for conn in retrans_conns[:5]:
                rate = conn.retransmission_rate
                if rate > 5:
                    style = "red"
                elif rate > 1:
                    style = "yellow"
                else:
                    style = "dim yellow"

                lines.append(
                    f"[{style}]{conn.retransmissions:4} ({rate:.1f}%)[/{style}] "
                    f"[dim]{conn.src_ip}:{conn.src_port} → {conn.dst_ip}:{conn.dst_port}[/dim]"
                )
        else:
            lines.append("[green]No retransmissions detected[/green]")

        return Panel(
            "\n".join(lines),
            title="[bold]Retransmissions[/bold]",
            border_style="red",
        )

    def _render_summary(self) -> Text:
        """Render summary line."""
        stats = self.tcp_tracker.get_stats()
        active = len(self.tcp_tracker.get_active_connections())
        retrans = stats["retransmission_stats"]["total_retransmissions"]

        retrans_status = (
            f"[red]{retrans} retransmissions[/red]"
            if retrans > 0 else "[green]No retransmissions[/green]"
        )

        return Text.from_markup(
            f"[dim]Total: {stats['total_connections']} | "
            f"Active: {active} | "
            f"Established: {stats['total_established']} | "
            f"{retrans_status}[/dim] | "
            f"[dim]Sort: {self.sort_by} (press 's' to change)[/dim]"
        )

    def render(self) -> RenderableType:
        """Render the TCP panel."""
        # Main connections table
        table = self._render_connections_table()

        # Side panels
        top_row = Columns([
            self._render_state_summary(),
            self._render_stats(),
        ], expand=True)

        bottom_row = Columns([
            self._render_rtt_summary(),
            self._render_retrans_summary(),
        ], expand=True)

        # Summary
        summary = self._render_summary()

        return Group(table, top_row, bottom_row, summary)
