"""Live traffic panel with selection and filtering."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.text import Text

from tracking.flow import Flow, FlowTracker
from geo.resolver import GeoInfo
from geo.dns_resolver import DNSResolver
from utils.network import format_bytes, format_packets, is_private_ip
from config import MAX_FLOWS_DISPLAY
from utils.logger import logger


@dataclass
class AggregatedDestination:
    """Aggregated view of connections to a destination."""
    dst_ip: str
    dst_port: int
    protocol_name: str
    connection_count: int
    total_bytes: int
    total_packets: int
    bytes_sent: int
    bytes_recv: int
    first_seen: float
    last_seen: float
    dst_geo: Optional[Dict] = None
    flow_keys: Set[str] = field(default_factory=set)

    @property
    def display_key(self) -> str:
        return f"{self.dst_ip}:{self.dst_port}-{self.protocol_name}"


class TrafficPanel:
    """Panel displaying live network traffic flows with selection."""

    def __init__(self, flow_tracker: FlowTracker, dns_resolver: DNSResolver = None):
        self.flow_tracker = flow_tracker
        self.dns_resolver = dns_resolver
        self.sort_by = "bytes"  # bytes, packets, time
        self.show_local = True

        # View mode: "flows" or "destinations"
        self.view_mode = "flows"

        # Filtering
        self.filter_protocol: Optional[str] = None
        self.filter_ip: str = ""
        self.filter_port: Optional[int] = None
        self.filter_min_bytes: int = 0

        # Selection state - use flow keys for persistent selection
        self.cursor_index: int = 0
        self.selected_keys: Set[str] = set()  # Flow keys (5-tuple identifiers)
        self._cached_flows: List[Flow] = []
        self._cached_destinations: List[AggregatedDestination] = []

        # Scroll state
        self.scroll_offset: int = 0
        self.visible_rows: int = MAX_FLOWS_DISPLAY

    def set_sort(self, sort_by: str) -> None:
        """Set sort order (bytes, packets, time)."""
        if sort_by in ("bytes", "packets", "time"):
            self.sort_by = sort_by

    def cycle_sort(self) -> str:
        """Cycle through sort modes and return new mode."""
        modes = ["bytes", "packets", "time"]
        current_idx = modes.index(self.sort_by)
        self.sort_by = modes[(current_idx + 1) % len(modes)]
        return self.sort_by

    def toggle_local(self) -> None:
        """Toggle showing local traffic."""
        self.show_local = not self.show_local

    def toggle_view_mode(self) -> str:
        """Toggle between flows and destinations view."""
        if self.view_mode == "flows":
            self.view_mode = "destinations"
        else:
            self.view_mode = "flows"
        self.cursor_index = 0
        self.scroll_offset = 0
        return self.view_mode

    def _aggregate_by_destination(self, flows: List[Flow]) -> List[AggregatedDestination]:
        """Aggregate flows by destination IP:port."""
        dest_map: Dict[str, AggregatedDestination] = {}

        for flow in flows:
            key = f"{flow.dst_ip}:{flow.dst_port}-{flow.protocol_name}"
            if key not in dest_map:
                dest_map[key] = AggregatedDestination(
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol_name=flow.protocol_name,
                    connection_count=0,
                    total_bytes=0,
                    total_packets=0,
                    bytes_sent=0,
                    bytes_recv=0,
                    first_seen=flow.first_seen,
                    last_seen=flow.last_seen,
                    dst_geo=flow.dst_geo,
                    flow_keys=set(),
                )
            dest = dest_map[key]
            dest.connection_count += 1
            dest.total_bytes += flow.total_bytes
            dest.total_packets += flow.total_packets
            dest.bytes_sent += flow.bytes_sent
            dest.bytes_recv += flow.bytes_recv
            dest.first_seen = min(dest.first_seen, flow.first_seen)
            dest.last_seen = max(dest.last_seen, flow.last_seen)
            dest.flow_keys.add(flow.flow_key)
            # Keep geo data if available
            if flow.dst_geo and not dest.dst_geo:
                dest.dst_geo = flow.dst_geo

        # Sort
        dests = list(dest_map.values())
        if self.sort_by == "bytes":
            dests.sort(key=lambda d: d.total_bytes, reverse=True)
        elif self.sort_by == "packets":
            dests.sort(key=lambda d: d.total_packets, reverse=True)
        elif self.sort_by == "time":
            dests.sort(key=lambda d: d.last_seen, reverse=True)

        return dests

    def set_protocol_filter(self, protocol: Optional[str]) -> None:
        """Filter by protocol name (TCP, UDP, ICMP, or None for all)."""
        self.filter_protocol = protocol

    def cycle_protocol_filter(self) -> Optional[str]:
        """Cycle through protocol filters."""
        protocols = [None, "TCP", "UDP", "ICMP"]
        try:
            idx = protocols.index(self.filter_protocol)
            self.filter_protocol = protocols[(idx + 1) % len(protocols)]
        except ValueError:
            self.filter_protocol = None
        return self.filter_protocol

    def set_ip_filter(self, ip_substring: str) -> None:
        """Filter flows containing this IP substring."""
        self.filter_ip = ip_substring

    def set_port_filter(self, port: Optional[int]) -> None:
        """Filter flows by port number."""
        self.filter_port = port

    def set_min_bytes_filter(self, min_bytes: int) -> None:
        """Filter flows with at least this many bytes."""
        self.filter_min_bytes = min_bytes

    def clear_filters(self) -> None:
        """Clear all filters."""
        self.filter_protocol = None
        self.filter_ip = ""
        self.filter_port = None
        self.filter_min_bytes = 0

    def _matches_filter(self, flow: Flow) -> bool:
        """Check if a flow matches current filters."""
        # Protocol filter
        if self.filter_protocol and flow.protocol_name != self.filter_protocol:
            return False

        # IP filter
        if self.filter_ip:
            if self.filter_ip not in flow.src_ip and self.filter_ip not in flow.dst_ip:
                return False

        # Port filter
        if self.filter_port is not None:
            if flow.src_port != self.filter_port and flow.dst_port != self.filter_port:
                return False

        # Min bytes filter
        if self.filter_min_bytes > 0 and flow.total_bytes < self.filter_min_bytes:
            return False

        # Local traffic filter
        if not self.show_local:
            if is_private_ip(flow.src_ip) and is_private_ip(flow.dst_ip):
                return False

        return True

    def _get_filtered_flows(self) -> List[Flow]:
        """Get flows with current filters applied."""
        flows = self.flow_tracker.get_flows()

        # Apply filters
        flows = [f for f in flows if self._matches_filter(f)]

        # Apply sorting
        if self.sort_by == "bytes":
            flows.sort(key=lambda f: f.total_bytes, reverse=True)
        elif self.sort_by == "packets":
            flows.sort(key=lambda f: f.total_packets, reverse=True)
        elif self.sort_by == "time":
            flows.sort(key=lambda f: f.last_seen, reverse=True)

        self._cached_flows = flows
        return flows

    def _format_location(self, geo) -> str:
        """Format geo location for display. Handles both GeoInfo objects and dicts."""
        if not geo:
            return "-"

        # Handle dict (from database)
        if isinstance(geo, dict):
            country = geo.get("country")
            if not country:
                return "-"
            city = geo.get("city")
            country_code = geo.get("country_code")
            if city and country_code:
                return f"{city}, {country_code}"
            return country

        # Handle GeoInfo object
        if not geo.query_success:
            return "-"
        if geo.is_private:
            return "Local"
        if geo.city and geo.country_code:
            return f"{geo.city}, {geo.country_code}"
        if geo.country:
            return geo.country
        return "-"

    def _get_hostname(self, ip: str, prefer_fqdn: bool = True) -> str:
        """Get hostname for an IP from DNS resolver.

        Args:
            ip: IP address to look up
            prefer_fqdn: If True, return full FQDN; if False, return domain
        """
        if not self.dns_resolver:
            return ""
        info = self.dns_resolver.get_cached(ip)
        if info:
            if prefer_fqdn and info.fqdn:
                # Return FQDN, truncated if too long
                if len(info.fqdn) > 40:
                    return info.fqdn[:37] + "..."
                return info.fqdn
            elif info.domain:
                return info.domain
            elif info.hostname:
                if len(info.hostname) > 25:
                    return info.hostname[:22] + "..."
                return info.hostname
        return ""

    # Navigation methods
    def move_up(self) -> None:
        """Move cursor up."""
        logger.debug(f"move_up: cursor={self.cursor_index}, scroll={self.scroll_offset}")
        if self.cursor_index > 0:
            self.cursor_index -= 1
            if self.cursor_index < self.scroll_offset:
                self.scroll_offset = self.cursor_index

    def _get_item_count(self) -> int:
        """Get the number of items in the current view."""
        if self.view_mode == "destinations":
            return len(self._cached_destinations)
        return len(self._cached_flows)

    def move_down(self) -> None:
        """Move cursor down."""
        max_index = self._get_item_count() - 1
        logger.debug(f"move_down: cursor={self.cursor_index}, max={max_index}, scroll={self.scroll_offset}")
        if self.cursor_index < max_index:
            self.cursor_index += 1
            if self.cursor_index >= self.scroll_offset + self.visible_rows:
                self.scroll_offset = self.cursor_index - self.visible_rows + 1

    def page_up(self) -> None:
        """Move cursor up by a page."""
        self.cursor_index = max(0, self.cursor_index - self.visible_rows)
        self.scroll_offset = max(0, self.scroll_offset - self.visible_rows)

    def page_down(self) -> None:
        """Move cursor down by a page."""
        item_count = self._get_item_count()
        max_index = item_count - 1
        self.cursor_index = min(max_index, self.cursor_index + self.visible_rows)
        self.scroll_offset = min(
            max(0, item_count - self.visible_rows),
            self.scroll_offset + self.visible_rows
        )

    def home(self) -> None:
        """Move to first item."""
        self.cursor_index = 0
        self.scroll_offset = 0

    def end(self) -> None:
        """Move to last item."""
        item_count = self._get_item_count()
        self.cursor_index = max(0, item_count - 1)
        self.scroll_offset = max(0, item_count - self.visible_rows)

    def toggle_selection(self) -> None:
        """Toggle selection of current item."""
        if self.view_mode == "destinations":
            # In destinations view, select/deselect all flows for this destination
            if 0 <= self.cursor_index < len(self._cached_destinations):
                dest = self._cached_destinations[self.cursor_index]
                # If any flows are selected, deselect all; otherwise select all
                if dest.flow_keys & self.selected_keys:
                    self.selected_keys -= dest.flow_keys
                else:
                    self.selected_keys |= dest.flow_keys
        else:
            # In flows view, toggle individual flow
            if 0 <= self.cursor_index < len(self._cached_flows):
                flow = self._cached_flows[self.cursor_index]
                key = flow.flow_key
                if key in self.selected_keys:
                    self.selected_keys.remove(key)
                else:
                    self.selected_keys.add(key)

    def select_all(self) -> None:
        """Select all visible items."""
        if self.view_mode == "destinations":
            # Select all flows from all destinations
            for dest in self._cached_destinations:
                self.selected_keys |= dest.flow_keys
        else:
            self.selected_keys = {f.flow_key for f in self._cached_flows}

    def clear_selection(self) -> None:
        """Clear all selections."""
        self.selected_keys.clear()

    def get_selected_flows(self) -> List[Flow]:
        """Get list of selected flows."""
        return [f for f in self._cached_flows if f.flow_key in self.selected_keys]

    def is_selected(self, flow: Flow) -> bool:
        """Check if a flow is selected."""
        return flow.flow_key in self.selected_keys

    def get_current_flow(self) -> Optional[Flow]:
        """Get the flow at cursor position."""
        if 0 <= self.cursor_index < len(self._cached_flows):
            return self._cached_flows[self.cursor_index]
        return None

    def render(self) -> RenderableType:
        """Render the traffic panel."""
        try:
            return self._render_internal()
        except Exception as e:
            logger.error(f"Error rendering traffic panel: {e}")
            from utils.logger import log_exception
            log_exception("Traffic panel render error")
            return Text(f"[red]Render error: {e}[/red]")

    def _render_internal(self) -> RenderableType:
        """Internal render method."""
        if self.view_mode == "destinations":
            return self._render_destinations_view()
        return self._render_flows_view()

    def _render_flows_view(self) -> RenderableType:
        """Render flows view."""
        flows = self._get_filtered_flows()

        # Ensure cursor is within bounds
        if flows:
            self.cursor_index = min(self.cursor_index, len(flows) - 1)
            self.cursor_index = max(0, self.cursor_index)
        else:
            self.cursor_index = 0

        # Build title with filter info
        title_parts = [f"[bold]Live Traffic - Flows[/bold] (sorted by {self.sort_by})"]
        filter_parts = []
        if self.filter_protocol:
            filter_parts.append(f"proto={self.filter_protocol}")
        if self.filter_ip:
            filter_parts.append(f"ip={self.filter_ip}")
        if self.filter_port:
            filter_parts.append(f"port={self.filter_port}")
        if filter_parts:
            title_parts.append(f"[dim]filters: {', '.join(filter_parts)}[/dim]")

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title=" | ".join(title_parts),
        )

        table.add_column("", width=3)  # Selection indicator
        table.add_column("Source", style="green", no_wrap=True, ratio=2)
        table.add_column("Destination", style="yellow", no_wrap=True, ratio=2)
        table.add_column("Dst Host", style="cyan", no_wrap=True, ratio=2)
        table.add_column("Proto", style="magenta", justify="center", width=5)
        table.add_column("↑ Sent", justify="right", width=9)
        table.add_column("↓ Recv", justify="right", width=9)
        table.add_column("Pkts", justify="right", width=7)
        table.add_column("Loc", style="dim", no_wrap=True, width=12)

        # Calculate visible range
        start_idx = self.scroll_offset
        end_idx = min(start_idx + self.visible_rows, len(flows))

        for idx in range(start_idx, end_idx):
            flow = flows[idx]
            src = f"{flow.src_ip}:{flow.src_port}" if flow.src_port else flow.src_ip
            dst = f"{flow.dst_ip}:{flow.dst_port}" if flow.dst_port else flow.dst_ip

            # Get hostname for destination
            hostname = self._get_hostname(flow.dst_ip)

            location = self._format_location(flow.dst_geo) if flow.dst_geo else "-"

            # Selection and cursor indicators
            is_cursor = idx == self.cursor_index
            is_selected = flow.flow_key in self.selected_keys

            if is_cursor and is_selected:
                indicator = "[bold white on blue]>*[/bold white on blue]"
                row_style = "bold white on blue"
            elif is_cursor:
                indicator = "[bold white on blue]> [/bold white on blue]"
                row_style = "on dark_blue"
            elif is_selected:
                indicator = "[green] *[/green]"
                row_style = "dim"
            else:
                indicator = "  "
                row_style = None

            table.add_row(
                indicator,
                src,
                dst,
                hostname or "-",
                flow.protocol_name,
                format_bytes(flow.bytes_sent),
                format_bytes(flow.bytes_recv),
                format_packets(flow.total_packets),
                location,
                style=row_style,
            )

        # Summary line
        total_bytes = self.flow_tracker.total_bytes
        total_packets = self.flow_tracker.total_packets
        flow_count = self.flow_tracker.flow_count
        filtered_count = len(flows)
        selected_count = len(self.selected_keys)

        summary_parts = [
            f"Showing: {filtered_count}/{flow_count}",
            f"Total: {format_bytes(total_bytes)}",
            f"Packets: {format_packets(total_packets)}",
        ]
        if selected_count > 0:
            summary_parts.append(f"Selected: {selected_count}")

        summary = f"[dim]{' | '.join(summary_parts)}[/dim]"

        return Group(table, Text.from_markup(summary))

    def _render_destinations_view(self) -> RenderableType:
        """Render aggregated destinations view."""
        flows = self._get_filtered_flows()
        destinations = self._aggregate_by_destination(flows)
        self._cached_destinations = destinations

        # Ensure cursor is within bounds
        if destinations:
            self.cursor_index = min(self.cursor_index, len(destinations) - 1)
            self.cursor_index = max(0, self.cursor_index)
        else:
            self.cursor_index = 0

        # Build title
        title_parts = [f"[bold]Live Traffic - Destinations[/bold] (sorted by {self.sort_by})"]
        filter_parts = []
        if self.filter_protocol:
            filter_parts.append(f"proto={self.filter_protocol}")
        if self.filter_ip:
            filter_parts.append(f"ip={self.filter_ip}")
        if filter_parts:
            title_parts.append(f"[dim]filters: {', '.join(filter_parts)}[/dim]")

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title=" | ".join(title_parts),
        )

        table.add_column("", width=3)  # Selection indicator
        table.add_column("Destination", style="yellow", no_wrap=True, ratio=2)
        table.add_column("Hostname", style="cyan", no_wrap=True, ratio=2)
        table.add_column("Proto", style="magenta", justify="center", width=5)
        table.add_column("Conns", justify="right", width=6)
        table.add_column("↑ Sent", justify="right", width=9)
        table.add_column("↓ Recv", justify="right", width=9)
        table.add_column("Pkts", justify="right", width=7)
        table.add_column("Loc", style="dim", no_wrap=True, width=12)

        # Calculate visible range
        start_idx = self.scroll_offset
        end_idx = min(start_idx + self.visible_rows, len(destinations))

        for idx in range(start_idx, end_idx):
            dest = destinations[idx]
            dst = f"{dest.dst_ip}:{dest.dst_port}" if dest.dst_port else dest.dst_ip

            # Get hostname for destination
            hostname = self._get_hostname(dest.dst_ip)

            location = self._format_location(dest.dst_geo) if dest.dst_geo else "-"

            # Selection and cursor indicators
            is_cursor = idx == self.cursor_index
            # Check if any of this destination's flows are selected
            is_selected = bool(dest.flow_keys & self.selected_keys)

            if is_cursor and is_selected:
                indicator = "[bold white on blue]>*[/bold white on blue]"
                row_style = "bold white on blue"
            elif is_cursor:
                indicator = "[bold white on blue]> [/bold white on blue]"
                row_style = "on dark_blue"
            elif is_selected:
                indicator = "[green] *[/green]"
                row_style = "dim"
            else:
                indicator = "  "
                row_style = None

            # Color connection count based on volume
            if dest.connection_count >= 10:
                conn_str = f"[bold yellow]{dest.connection_count}[/bold yellow]"
            elif dest.connection_count >= 5:
                conn_str = f"[yellow]{dest.connection_count}[/yellow]"
            else:
                conn_str = str(dest.connection_count)

            table.add_row(
                indicator,
                dst,
                hostname or "-",
                dest.protocol_name,
                conn_str,
                format_bytes(dest.bytes_sent),
                format_bytes(dest.bytes_recv),
                format_packets(dest.total_packets),
                location,
                style=row_style,
            )

        # Summary line
        total_bytes = self.flow_tracker.total_bytes
        flow_count = self.flow_tracker.flow_count
        dest_count = len(destinations)
        selected_count = len(self.selected_keys)

        summary_parts = [
            f"Destinations: {dest_count}",
            f"Flows: {flow_count}",
            f"Total: {format_bytes(total_bytes)}",
        ]
        if selected_count > 0:
            summary_parts.append(f"Selected flows: {selected_count}")

        summary = f"[dim]{' | '.join(summary_parts)}[/dim]"

        return Group(table, Text.from_markup(summary))
