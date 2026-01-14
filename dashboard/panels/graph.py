"""Connection graph panel for network visualization."""

from typing import Optional
from enum import Enum, auto

from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.columns import Columns
from rich.text import Text

from security.graph import ConnectionGraph
from utils.network import format_bytes


class GraphViewMode(Enum):
    """Graph display modes."""
    TABLE = auto()
    TREE = auto()
    MATRIX = auto()
    STATS = auto()


class GraphPanel:
    """Panel displaying network connection graph."""

    def __init__(self, graph: ConnectionGraph):
        self.graph = graph
        self.view_mode = GraphViewMode.TABLE
        self.max_nodes = 30
        self.min_bytes = 0
        self.selected_ip: Optional[str] = None

    def cycle_view_mode(self) -> str:
        """Cycle through view modes."""
        modes = list(GraphViewMode)
        current_idx = modes.index(self.view_mode)
        next_idx = (current_idx + 1) % len(modes)
        self.view_mode = modes[next_idx]
        return self.view_mode.name.lower()

    def set_min_bytes(self, min_bytes: int) -> None:
        """Set minimum bytes threshold for display."""
        self.min_bytes = min_bytes

    def set_max_nodes(self, max_nodes: int) -> None:
        """Set maximum nodes to display."""
        self.max_nodes = max_nodes

    def _render_table_view(self) -> Panel:
        """Render connections as a table."""
        if not self.graph.edges:
            return Panel("[dim]No connections yet[/dim]", title="[bold]Connection Graph[/bold]", border_style="blue")

        table = Table(show_header=True, header_style="bold", box=None, expand=True)
        table.add_column("Source", style="cyan", no_wrap=True)
        table.add_column("", justify="center", width=4)
        table.add_column("Destination", style="green", no_wrap=True)
        table.add_column("Traffic", justify="right", style="yellow")
        table.add_column("Packets", justify="right")
        table.add_column("Proto", justify="center")
        table.add_column("Ports", style="dim")

        # Sort edges by traffic
        sorted_edges = sorted(
            self.graph.edges.values(),
            key=lambda e: e.total_bytes,
            reverse=True
        )[:self.max_nodes]

        # Filter by minimum bytes
        if self.min_bytes > 0:
            sorted_edges = [e for e in sorted_edges if e.total_bytes >= self.min_bytes]

        for edge in sorted_edges:
            src_node = self.graph.nodes.get(edge.src_ip)
            dst_node = self.graph.nodes.get(edge.dst_ip)

            src_label = src_node.label if src_node else edge.src_ip
            dst_label = dst_node.label if dst_node else edge.dst_ip

            # Truncate long labels
            src_label = src_label[:25] + "..." if len(src_label) > 25 else src_label
            dst_label = dst_label[:25] + "..." if len(dst_label) > 25 else dst_label

            # Style based on local/external
            src_style = "cyan" if (src_node and src_node.is_local) else "yellow"
            dst_style = "green" if (dst_node and dst_node.is_local) else "red"

            arrow = "<->" if edge.is_bidirectional else " ->"

            ports = ",".join(str(p) for p in sorted(edge.ports)[:3])
            if len(edge.ports) > 3:
                ports += f"+{len(edge.ports)-3}"

            table.add_row(
                Text(src_label, style=src_style),
                arrow,
                Text(dst_label, style=dst_style),
                format_bytes(edge.total_bytes),
                str(edge.packets),
                edge.protocol,
                ports,
            )

        title = f"[bold]Connection Graph[/bold] - Table View ({len(self.graph.edges)} connections)"
        return Panel(table, title=title, border_style="blue")

    def _render_tree_view(self) -> Panel:
        """Render connections as a tree."""
        if not self.graph.nodes:
            return Panel("[dim]No nodes yet[/dim]", title="[bold]Connection Tree[/bold]", border_style="blue")

        tree_text = self.graph.render_tree(max_depth=4)
        return Panel(tree_text, title="[bold]Connection Tree[/bold]", border_style="blue")

    def _render_matrix_view(self) -> Panel:
        """Render connections as a matrix."""
        if not self.graph.nodes:
            return Panel("[dim]No nodes yet[/dim]", title="[bold]Connection Matrix[/bold]", border_style="blue")

        matrix_text = self.graph.render_matrix(max_nodes=12)
        return Panel(matrix_text, title="[bold]Connection Matrix[/bold]", border_style="blue")

    def _render_stats_view(self) -> Panel:
        """Render graph statistics."""
        stats_text = self.graph.render_stats()
        return Panel(stats_text, title="[bold]Graph Statistics[/bold]", border_style="blue")

    def _render_summary(self) -> Panel:
        """Render graph summary."""
        summary = self.graph.get_summary()

        lines = []
        lines.append(f"[cyan]Total Nodes:[/cyan]      {summary['total_nodes']:>6}")
        lines.append(f"  [green]Local:[/green]          {summary['local_nodes']:>6}")
        lines.append(f"  [yellow]External:[/yellow]       {summary['external_nodes']:>6}")
        lines.append("")
        lines.append(f"[cyan]Total Edges:[/cyan]      {summary['total_edges']:>6}")
        lines.append(f"  [magenta]Bidirectional:[/magenta]  {summary['bidirectional_edges']:>6}")
        lines.append("")
        lines.append(f"[cyan]Total Traffic:[/cyan]    {format_bytes(summary['total_bytes']):>10}")

        return Panel("\n".join(lines), title="[bold]Summary[/bold]", border_style="blue")

    def _render_top_nodes(self) -> Panel:
        """Render top nodes by traffic."""
        if not self.graph.nodes:
            return Panel("[dim]No nodes[/dim]", title="[bold]Top Nodes[/bold]", border_style="blue")

        sorted_nodes = sorted(
            self.graph.nodes.values(),
            key=lambda n: n.total_bytes_in + n.total_bytes_out,
            reverse=True
        )[:10]

        lines = []
        for i, node in enumerate(sorted_nodes, 1):
            total = node.total_bytes_in + node.total_bytes_out
            label = node.label[:30] if len(node.label) > 30 else node.label

            # Style based on local/external
            style = "cyan" if node.is_local else "yellow"
            country = f"[{node.country_code}]" if node.country_code else ""

            lines.append(f"{i:2}. [{style}]{label:30}[/{style}] {country:4} {format_bytes(total):>10}")

        return Panel("\n".join(lines), title="[bold]Top Nodes by Traffic[/bold]", border_style="blue")

    def _render_external_connections(self) -> Panel:
        """Render external (non-local) connections summary."""
        external_nodes = [n for n in self.graph.nodes.values() if not n.is_local]

        if not external_nodes:
            return Panel("[dim]No external connections[/dim]",
                        title="[bold]External Hosts[/bold]", border_style="blue")

        # Group by country
        by_country = {}
        for node in external_nodes:
            country = node.country_code or "??"
            if country not in by_country:
                by_country[country] = {"count": 0, "bytes": 0}
            by_country[country]["count"] += 1
            by_country[country]["bytes"] += node.total_bytes_in + node.total_bytes_out

        # Sort by traffic
        sorted_countries = sorted(by_country.items(), key=lambda x: x[1]["bytes"], reverse=True)[:8]

        lines = []
        max_bytes = sorted_countries[0][1]["bytes"] if sorted_countries else 1
        for country, stats in sorted_countries:
            bar_len = int(15 * stats["bytes"] / max_bytes)
            bar = "█" * bar_len
            lines.append(f"[cyan]{country:4}[/cyan] [green]{bar:15}[/green] {stats['count']:3} hosts {format_bytes(stats['bytes']):>10}")

        return Panel("\n".join(lines), title="[bold]External Hosts by Country[/bold]", border_style="blue")

    def render(self) -> RenderableType:
        """Render the graph panel."""
        # Main view based on mode
        if self.view_mode == GraphViewMode.TABLE:
            main_view = self._render_table_view()
        elif self.view_mode == GraphViewMode.TREE:
            main_view = self._render_tree_view()
        elif self.view_mode == GraphViewMode.MATRIX:
            main_view = self._render_matrix_view()
        else:  # STATS
            main_view = self._render_stats_view()

        # Bottom row: summary and top nodes
        bottom_row = Columns([
            self._render_summary(),
            self._render_top_nodes(),
            self._render_external_connections(),
        ], expand=True)

        return Group(main_view, bottom_row)
