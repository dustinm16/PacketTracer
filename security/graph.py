"""ASCII connection graph visualization."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from tracking.flow import Flow
from utils.network import is_private_ip, format_bytes


@dataclass
class Node:
    """Represents a node (IP) in the connection graph."""
    ip: str
    hostname: Optional[str] = None
    is_local: bool = False
    is_gateway: bool = False
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    connections: int = 0
    country_code: str = ""

    @property
    def label(self) -> str:
        """Get display label for the node."""
        if self.hostname:
            # Truncate long hostnames
            name = self.hostname[:20] + "..." if len(self.hostname) > 20 else self.hostname
            return f"{name}"
        return self.ip

    @property
    def short_ip(self) -> str:
        """Get shortened IP for display."""
        parts = self.ip.split(".")
        if len(parts) == 4:
            return f".{parts[3]}"
        return self.ip[:15]


@dataclass
class Edge:
    """Represents a connection between two nodes."""
    src_ip: str
    dst_ip: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets: int = 0
    protocol: str = "TCP"
    ports: Set[int] = field(default_factory=set)

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv

    @property
    def is_bidirectional(self) -> bool:
        return self.bytes_sent > 0 and self.bytes_recv > 0


class ConnectionGraph:
    """Builds and renders ASCII connection graphs."""

    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str], Edge] = {}
        self.local_ips: Set[str] = set()

    def clear(self) -> None:
        """Clear the graph."""
        self.nodes.clear()
        self.edges.clear()

    def add_flow(self, flow: Flow) -> None:
        """Add a flow to the graph."""
        src_ip = flow.src_ip
        dst_ip = flow.dst_ip

        # Add/update source node
        if src_ip not in self.nodes:
            self.nodes[src_ip] = Node(
                ip=src_ip,
                is_local=is_private_ip(src_ip),
            )
        src_node = self.nodes[src_ip]
        src_node.total_bytes_out += flow.bytes_sent
        src_node.total_bytes_in += flow.bytes_recv
        src_node.connections += 1

        # Add/update destination node
        if dst_ip not in self.nodes:
            self.nodes[dst_ip] = Node(
                ip=dst_ip,
                is_local=is_private_ip(dst_ip),
            )
        dst_node = self.nodes[dst_ip]
        dst_node.total_bytes_in += flow.bytes_sent
        dst_node.total_bytes_out += flow.bytes_recv
        dst_node.connections += 1

        # Track local IPs
        if src_node.is_local:
            self.local_ips.add(src_ip)
        if dst_node.is_local:
            self.local_ips.add(dst_ip)

        # Add/update edge
        edge_key = (min(src_ip, dst_ip), max(src_ip, dst_ip))
        if edge_key not in self.edges:
            self.edges[edge_key] = Edge(src_ip=src_ip, dst_ip=dst_ip)
        edge = self.edges[edge_key]
        edge.bytes_sent += flow.bytes_sent
        edge.bytes_recv += flow.bytes_recv
        edge.packets += flow.total_packets
        edge.ports.add(flow.dst_port)
        edge.protocol = flow.protocol_name

    def add_flows(self, flows: List[Flow]) -> None:
        """Add multiple flows to the graph."""
        for flow in flows:
            self.add_flow(flow)

    def set_hostname(self, ip: str, hostname: str) -> None:
        """Set hostname for a node."""
        if ip in self.nodes:
            self.nodes[ip].hostname = hostname

    def set_country(self, ip: str, country_code: str) -> None:
        """Set country code for a node."""
        if ip in self.nodes:
            self.nodes[ip].country_code = country_code

    def render_simple(self, max_nodes: int = 20, min_bytes: int = 0) -> str:
        """Render a simple text-based connection list."""
        lines = []
        lines.append("=" * 70)
        lines.append("CONNECTION GRAPH")
        lines.append("=" * 70)

        if not self.edges:
            lines.append("No connections to display.")
            return "\n".join(lines)

        # Sort edges by traffic
        sorted_edges = sorted(
            self.edges.values(),
            key=lambda e: e.total_bytes,
            reverse=True
        )[:max_nodes]

        # Filter by minimum bytes
        if min_bytes > 0:
            sorted_edges = [e for e in sorted_edges if e.total_bytes >= min_bytes]

        for edge in sorted_edges:
            src_node = self.nodes.get(edge.src_ip)
            dst_node = self.nodes.get(edge.dst_ip)

            src_label = src_node.label if src_node else edge.src_ip
            dst_label = dst_node.label if dst_node else edge.dst_ip

            # Direction arrow
            if edge.is_bidirectional:
                arrow = "<-->"
            else:
                arrow = " --> "

            # Traffic info
            traffic = format_bytes(edge.total_bytes)
            ports_str = ",".join(str(p) for p in sorted(edge.ports)[:3])
            if len(edge.ports) > 3:
                ports_str += "..."

            lines.append(f"{src_label:>25} {arrow} {dst_label:<25} [{traffic:>10}] {edge.protocol}:{ports_str}")

        lines.append("=" * 70)
        lines.append(f"Nodes: {len(self.nodes)} | Connections: {len(self.edges)}")

        return "\n".join(lines)

    def render_tree(self, root_ip: Optional[str] = None, max_depth: int = 3) -> str:
        """Render a tree view from a root IP."""
        lines = []

        # Find root - use local IP with most connections or first local IP
        if root_ip is None:
            local_nodes = [(ip, self.nodes[ip]) for ip in self.local_ips if ip in self.nodes]
            if local_nodes:
                root_ip = max(local_nodes, key=lambda x: x[1].connections)[0]
            elif self.nodes:
                root_ip = next(iter(self.nodes.keys()))
            else:
                return "No nodes in graph."

        root_node = self.nodes.get(root_ip)
        if not root_node:
            return f"Root IP {root_ip} not found in graph."

        lines.append("CONNECTION TREE")
        lines.append("=" * 60)

        # Build adjacency list
        adjacency: Dict[str, List[Tuple[str, Edge]]] = defaultdict(list)
        for (ip1, ip2), edge in self.edges.items():
            adjacency[ip1].append((ip2, edge))
            adjacency[ip2].append((ip1, edge))

        # BFS to build tree
        visited: Set[str] = {root_ip}
        queue: List[Tuple[str, int, str]] = [(root_ip, 0, "")]  # (ip, depth, prefix)

        while queue:
            ip, depth, prefix = queue.pop(0)
            if depth > max_depth:
                continue

            node = self.nodes.get(ip)
            if not node:
                continue

            # Node label
            label = node.label
            if node.country_code:
                label += f" [{node.country_code}]"

            # Connection info
            total = node.total_bytes_in + node.total_bytes_out
            info = f"({format_bytes(total)}, {node.connections} conn)"

            if depth == 0:
                lines.append(f"[ROOT] {label} {info}")
            else:
                lines.append(f"{prefix}├── {label} {info}")

            # Get children
            children = []
            for neighbor_ip, edge in adjacency[ip]:
                if neighbor_ip not in visited:
                    children.append((neighbor_ip, edge))
                    visited.add(neighbor_ip)

            # Sort children by traffic
            children.sort(key=lambda x: x[1].total_bytes, reverse=True)

            # Add children to queue
            for i, (child_ip, edge) in enumerate(children[:10]):  # Limit children
                is_last = (i == len(children) - 1) or (i == 9)
                child_prefix = prefix + ("    " if is_last else "│   ")
                queue.append((child_ip, depth + 1, child_prefix))

        lines.append("=" * 60)
        return "\n".join(lines)

    def render_matrix(self, max_nodes: int = 10) -> str:
        """Render a connection matrix."""
        lines = []
        lines.append("CONNECTION MATRIX")
        lines.append("=" * 60)

        if not self.nodes:
            lines.append("No nodes in graph.")
            return "\n".join(lines)

        # Get top nodes by traffic
        sorted_nodes = sorted(
            self.nodes.values(),
            key=lambda n: n.total_bytes_in + n.total_bytes_out,
            reverse=True
        )[:max_nodes]

        node_ips = [n.ip for n in sorted_nodes]

        # Header
        header = "             "
        for i, ip in enumerate(node_ips):
            header += f" [{i:2d}]"
        lines.append(header)

        # Matrix rows
        for i, src_ip in enumerate(node_ips):
            src_node = self.nodes[src_ip]
            label = src_node.short_ip if len(src_node.short_ip) <= 8 else src_node.short_ip[:8]
            row = f"[{i:2d}] {label:>8}"

            for j, dst_ip in enumerate(node_ips):
                if i == j:
                    row += "  -- "
                else:
                    # Check for edge
                    edge_key = (min(src_ip, dst_ip), max(src_ip, dst_ip))
                    if edge_key in self.edges:
                        edge = self.edges[edge_key]
                        # Show traffic level
                        mb = edge.total_bytes / 1_000_000
                        if mb >= 100:
                            row += " ### "
                        elif mb >= 10:
                            row += "  ## "
                        elif mb >= 1:
                            row += "   # "
                        else:
                            row += "   . "
                    else:
                        row += "     "

            lines.append(row)

        # Legend
        lines.append("")
        lines.append("Legend: ### >100MB  ## >10MB  # >1MB  . <1MB")

        # Node index
        lines.append("")
        lines.append("Nodes:")
        for i, ip in enumerate(node_ips):
            node = self.nodes[ip]
            label = node.hostname or ip
            traffic = format_bytes(node.total_bytes_in + node.total_bytes_out)
            lines.append(f"  [{i:2d}] {label} ({traffic})")

        return "\n".join(lines)

    def render_stats(self) -> str:
        """Render graph statistics."""
        lines = []
        lines.append("GRAPH STATISTICS")
        lines.append("=" * 60)

        total_nodes = len(self.nodes)
        local_nodes = sum(1 for n in self.nodes.values() if n.is_local)
        external_nodes = total_nodes - local_nodes

        total_edges = len(self.edges)
        total_bytes = sum(e.total_bytes for e in self.edges.values())
        bidirectional = sum(1 for e in self.edges.values() if e.is_bidirectional)

        lines.append(f"Total Nodes:     {total_nodes}")
        lines.append(f"  Local:         {local_nodes}")
        lines.append(f"  External:      {external_nodes}")
        lines.append("")
        lines.append(f"Total Edges:     {total_edges}")
        lines.append(f"  Bidirectional: {bidirectional}")
        lines.append("")
        lines.append(f"Total Traffic:   {format_bytes(total_bytes)}")

        # Top talkers
        if self.nodes:
            lines.append("")
            lines.append("Top Talkers (by bytes):")
            sorted_nodes = sorted(
                self.nodes.values(),
                key=lambda n: n.total_bytes_in + n.total_bytes_out,
                reverse=True
            )[:5]
            for i, node in enumerate(sorted_nodes, 1):
                total = node.total_bytes_in + node.total_bytes_out
                label = node.hostname or node.ip
                lines.append(f"  {i}. {label}: {format_bytes(total)}")

        # Top connections
        if self.edges:
            lines.append("")
            lines.append("Top Connections:")
            sorted_edges = sorted(
                self.edges.values(),
                key=lambda e: e.total_bytes,
                reverse=True
            )[:5]
            for i, edge in enumerate(sorted_edges, 1):
                src = self.nodes.get(edge.src_ip)
                dst = self.nodes.get(edge.dst_ip)
                src_label = src.label if src else edge.src_ip
                dst_label = dst.label if dst else edge.dst_ip
                lines.append(f"  {i}. {src_label} <-> {dst_label}: {format_bytes(edge.total_bytes)}")

        lines.append("=" * 60)
        return "\n".join(lines)

    def get_rich_table(self):
        """Get a Rich table for dashboard display."""
        from rich.table import Table
        from rich.text import Text

        table = Table(title="Connection Graph", expand=True)
        table.add_column("Source", style="cyan", no_wrap=True)
        table.add_column("", justify="center", width=4)
        table.add_column("Destination", style="green", no_wrap=True)
        table.add_column("Traffic", justify="right", style="yellow")
        table.add_column("Proto", justify="center")
        table.add_column("Ports", style="dim")

        # Sort edges by traffic
        sorted_edges = sorted(
            self.edges.values(),
            key=lambda e: e.total_bytes,
            reverse=True
        )[:20]

        for edge in sorted_edges:
            src_node = self.nodes.get(edge.src_ip)
            dst_node = self.nodes.get(edge.dst_ip)

            src_label = src_node.label if src_node else edge.src_ip
            dst_label = dst_node.label if dst_node else edge.dst_ip

            # Color based on local/external
            src_style = "cyan" if (src_node and src_node.is_local) else "yellow"
            dst_style = "green" if (dst_node and dst_node.is_local) else "red"

            arrow = "<->" if edge.is_bidirectional else " ->"

            ports = ",".join(str(p) for p in sorted(edge.ports)[:3])
            if len(edge.ports) > 3:
                ports += "..."

            table.add_row(
                Text(src_label[:25], style=src_style),
                arrow,
                Text(dst_label[:25], style=dst_style),
                format_bytes(edge.total_bytes),
                edge.protocol,
                ports,
            )

        return table

    def get_summary(self) -> Dict:
        """Get graph summary as dict."""
        return {
            "total_nodes": len(self.nodes),
            "local_nodes": sum(1 for n in self.nodes.values() if n.is_local),
            "external_nodes": sum(1 for n in self.nodes.values() if not n.is_local),
            "total_edges": len(self.edges),
            "total_bytes": sum(e.total_bytes for e in self.edges.values()),
            "bidirectional_edges": sum(1 for e in self.edges.values() if e.is_bidirectional),
        }
