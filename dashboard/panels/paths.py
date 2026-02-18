"""Path visualization panel."""

from typing import List, Optional, Dict, Set, Union, TYPE_CHECKING

from rich.table import Table
from rich.console import Group, RenderableType
from rich.text import Text

from tracking.path import PathTracer, TracerouteResult, HopResult
from tracking.hops import HopAnalyzer
from tracking.flow import Flow
from geo.resolver import GeoResolver
from geo.dns_resolver import DNSResolver
from geo.ownership import OwnershipResolver
from config import MAX_PATHS_DISPLAY

if TYPE_CHECKING:
    from tracking.db_path import DBPathTracer
    from db.repositories.hop_repo import HopRepository
    from db.repositories.route_repo import RouteRepository


class PathsPanel:
    """Panel displaying network path information."""

    def __init__(
        self,
        path_tracer: Union[PathTracer, "DBPathTracer"],
        hop_analyzer: HopAnalyzer,
        geo_resolver: Optional[GeoResolver] = None,
        dns_resolver: Optional[DNSResolver] = None,
        ownership_resolver: Optional[OwnershipResolver] = None,
        hop_repo: Optional["HopRepository"] = None,
        route_repo: Optional["RouteRepository"] = None,
    ):
        self.path_tracer = path_tracer
        self.hop_analyzer = hop_analyzer
        self.geo_resolver = geo_resolver
        self.dns_resolver = dns_resolver
        self.ownership_resolver = ownership_resolver
        self.hop_repo = hop_repo
        self.route_repo = route_repo
        self.current_trace: Optional[TracerouteResult] = None
        self.selected_ip: Optional[str] = None
        self._selected_flows: Optional[List[Flow]] = None

        # Track multiple traceroutes
        self._traces: Dict[str, TracerouteResult] = {}  # dst_ip -> result
        self._pending_traces: Set[str] = set()  # IPs currently being traced
        self._auto_traced: Set[str] = set()  # IPs we've auto-traced this session

    def set_selected_flows(self, flows: Optional[List[Flow]]) -> None:
        """Set selected flows for display."""
        self._selected_flows = flows if flows else None

    def trace_selected_flows(self) -> int:
        """Start traces for selected flow destinations. Returns count started."""
        if not self._selected_flows:
            return 0

        count = 0
        for flow in self._selected_flows:
            dst_ip = flow.dst_ip
            # Only trace external IPs we haven't traced yet
            if dst_ip and not dst_ip.startswith(('10.', '192.168.', '172.16.', '127.')):
                if dst_ip not in self._traces and dst_ip not in self._pending_traces:
                    self._auto_traced.add(dst_ip)
                    self.start_trace(dst_ip)
                    count += 1
        return count

    def _get_selected_ips(self) -> Set[str]:
        """Get set of IPs from selected flows."""
        if not self._selected_flows:
            return set()
        ips = set()
        for flow in self._selected_flows:
            ips.add(flow.src_ip)
            ips.add(flow.dst_ip)
        return ips

    def _get_selected_destinations(self) -> Set[str]:
        """Get set of destination IPs from selected flows."""
        if not self._selected_flows:
            return set()
        return {flow.dst_ip for flow in self._selected_flows if flow.dst_ip}

    def start_trace(self, target: str) -> None:
        """Start a traceroute to target."""
        self._pending_traces.add(target)

        def on_complete(result: TracerouteResult):
            self._traces[result.target_ip] = result
            self._pending_traces.discard(target)
            self._pending_traces.discard(result.target_ip)
            self.current_trace = result
            # Resolve geo, DNS, and ownership for each hop
            for hop in result.hops:
                if hop.ip:
                    if self.geo_resolver:
                        self.geo_resolver.resolve_async(hop.ip)
                    if self.dns_resolver:
                        self.dns_resolver.resolve_async(hop.ip)
                    if self.ownership_resolver:
                        self.ownership_resolver.resolve_async(hop.ip)

        self.path_tracer.trace_async(target, callback=on_complete)

    def get_trace(self, ip: str) -> Optional[TracerouteResult]:
        """Get cached traceroute result for an IP."""
        # First check in-memory cache
        result = self._traces.get(ip) or self.path_tracer.get_cached(ip)
        if result:
            return result

        # Check database if available
        if self.hop_repo:
            db_result = self._get_trace_from_db(ip)
            if db_result:
                return db_result

        return None

    def _get_trace_from_db(self, target_ip: str) -> Optional[TracerouteResult]:
        """Get traceroute from database and convert to TracerouteResult."""
        if not self.hop_repo:
            return None

        traces = self.hop_repo.get_traceroutes(target_ip=target_ip, limit=1)
        if not traces:
            return None

        trace = traces[0]
        hops = self.hop_repo.get_hops(trace.id)

        # Convert HopRecord to HopResult
        hop_results = []
        for hop in hops:
            hop_result = HopResult(
                ttl=hop.hop_number,
                ip=hop.ip,
                hostname=hop.hostname,
                rtt_ms=[hop.rtt_avg] if hop.rtt_avg else [],
                is_destination=hop.is_target,
                is_timeout=hop.is_timeout,
            )
            hop_results.append(hop_result)

        return TracerouteResult(
            target=trace.target_hostname or trace.target_ip,
            target_ip=trace.target_ip,
            hops=hop_results,
            completed=trace.reached_target,
            start_time=trace.started_at,
            end_time=trace.completed_at or trace.started_at,
        )

    def clear_traces(self) -> None:
        """Clear all cached traces."""
        self._traces.clear()
        self._auto_traced.clear()
        self.current_trace = None
        self.path_tracer.clear_cache()

    def refresh_traces(self) -> int:
        """Re-run traces for selected destinations. Returns count of traces started."""
        count = 0
        for dst_ip in self._get_selected_destinations():
            if dst_ip and not dst_ip.startswith(('10.', '192.168.', '172.16.', '127.')):
                if dst_ip not in self._pending_traces:
                    self._traces.pop(dst_ip, None)
                    self._auto_traced.discard(dst_ip)
                    self.start_trace(dst_ip)
                    count += 1
        return count

    def _get_hostname(self, ip: str, prefer_fqdn: bool = True) -> str:
        """Get hostname/FQDN for an IP.

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
                if len(info.hostname) > 30:
                    return info.hostname[:27] + "..."
                return info.hostname
        return ""

    def _get_ownership(self, ip: str) -> str:
        """Get ownership/ASN info for an IP."""
        if not self.ownership_resolver:
            return ""
        info = self.ownership_resolver.get_cached(ip)
        if info:
            if info.as_name:
                name = info.as_name[:20] if len(info.as_name) > 20 else info.as_name
                if info.asn:
                    return f"{name} (AS{info.asn})"
                return name
            if info.org:
                return info.org[:25] if len(info.org) > 25 else info.org
        return ""

    def _format_geo_location(self, geo) -> str:
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
        if geo.city and geo.country_code:
            return f"{geo.city}, {geo.country_code}"
        if geo.country:
            return geo.country
        return "-"

    def _get_geo_owner(self, geo) -> str:
        """Get ISP/org from geo data. Handles both GeoInfo objects and dicts."""
        if not geo:
            return "-"

        if isinstance(geo, dict):
            owner = geo.get("isp") or geo.get("org") or "-"
        else:
            if not geo.query_success:
                return "-"
            owner = geo.isp or geo.org or "-"

        if len(owner) > 25:
            return owner[:22] + "..."
        return owner

    def _render_traceroute(self, trace: TracerouteResult) -> Table:
        """Render a traceroute result as a table."""
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title=f"[bold]Traceroute to {trace.target}[/bold] ({trace.target_ip})",
        )

        table.add_column("Hop", justify="center", width=4)
        table.add_column("IP Address", style="green", no_wrap=True, width=16)
        table.add_column("FQDN", style="yellow", no_wrap=True)
        table.add_column("RTT", justify="right", width=9)
        table.add_column("Location", style="cyan", width=15)
        table.add_column("Owner/ASN", style="magenta", no_wrap=True)

        for hop in trace.hops:
            if hop.is_timeout:
                table.add_row(
                    str(hop.ttl),
                    "*",
                    "Request timed out",
                    "*",
                    "-",
                    "-",
                    style="dim",
                )
            else:
                rtt_str = f"{hop.avg_rtt:.1f} ms" if hop.avg_rtt else "-"

                # Get hostname - prefer our DNS resolver, fall back to traceroute's
                hostname = self._get_hostname(hop.ip) if hop.ip else ""
                if not hostname and hop.hostname:
                    hostname = hop.hostname[:30] if len(hop.hostname) > 30 else hop.hostname
                hostname = hostname or "-"

                # Get geo info
                location = "-"
                owner = "-"
                if hop.ip:
                    if self.geo_resolver:
                        geo = self.geo_resolver.get_result(hop.ip)
                        location = self._format_geo_location(geo)
                        # Use geo ISP/org as fallback for owner
                        if not self.ownership_resolver:
                            owner = self._get_geo_owner(geo)

                    # Get ownership info (preferred over geo ISP)
                    ownership = self._get_ownership(hop.ip)
                    if ownership:
                        owner = ownership

                style = "bold green" if hop.is_destination else None

                table.add_row(
                    str(hop.ttl),
                    hop.ip,
                    hostname,
                    rtt_str,
                    location,
                    owner,
                    style=style,
                )

        return table

    def _render_hop_summary(self) -> Table:
        """Render summary of observed hops."""
        hop_info = self.hop_analyzer.get_all_hop_info()

        # Filter by selected flows if any
        selected_ips = self._get_selected_ips()
        if selected_ips:
            hop_info = [h for h in hop_info if h.ip in selected_ips]
            title = f"[bold]Observed Hosts by Hop Distance[/bold] [yellow]({len(selected_ips)} selected IPs)[/yellow]"
        else:
            title = "[bold]Observed Hosts by Hop Distance[/bold]"

        hop_info.sort(key=lambda h: h.avg_hops)

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title=title,
        )

        table.add_column("IP Address", style="green", no_wrap=True, width=16)
        table.add_column("FQDN", style="yellow", no_wrap=True)
        table.add_column("Hops", justify="center", width=6)
        table.add_column("Samples", justify="right", width=7)
        table.add_column("Location", style="cyan", width=15)
        table.add_column("Owner", style="magenta", no_wrap=True)

        for info in hop_info[:MAX_PATHS_DISPLAY]:
            # Get hostname
            hostname = self._get_hostname(info.ip) or "-"

            # Get geo info
            location = "-"
            owner = "-"
            if self.geo_resolver:
                geo = self.geo_resolver.get_result(info.ip)
                location = self._format_geo_location(geo)
                if not self.ownership_resolver:
                    owner = self._get_geo_owner(geo)

            # Get ownership info
            ownership = self._get_ownership(info.ip)
            if ownership:
                owner = ownership

            table.add_row(
                info.ip,
                hostname,
                f"{info.avg_hops:.1f}",
                str(info.sample_count),
                location,
                owner,
            )

        return table

    def _render_flow_paths(self) -> RenderableType:
        """Render paths for selected flows."""
        elements = []
        selected_dests = self._get_selected_destinations()

        if not selected_dests:
            return Text("[dim]No flows selected. Select flows in Traffic view and switch here to see their routes.[/dim]")

        # Show status of pending traces
        pending = selected_dests & self._pending_traces
        if pending:
            elements.append(Text(f"[yellow]Tracing {len(pending)} destination(s)...[/yellow]"))
            elements.append(Text(""))

        # Show traceroutes for selected destinations
        traces_shown = 0
        for dst_ip in selected_dests:
            trace = self.get_trace(dst_ip)
            if trace:
                elements.append(self._render_traceroute(trace))
                status_text = "Complete" if trace.completed else "In Progress"
                elements.append(Text(f"[dim]Hops: {trace.total_hops} | Status: {status_text} | Duration: {trace.duration:.1f}s[/dim]"))
                elements.append(Text(""))  # Spacer
                traces_shown += 1

        if traces_shown == 0 and not pending:
            # No traces available yet - show what we know from flows
            elements.append(self._render_flow_summary())

        return Group(*elements)

    def _render_flow_summary(self) -> Table:
        """Render summary of selected flows (before traces complete)."""
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title="[bold]Selected Flow Destinations[/bold]",
        )

        table.add_column("Destination", style="yellow", no_wrap=True, width=18)
        table.add_column("FQDN", style="cyan", no_wrap=True)
        table.add_column("Port", justify="right", width=6)
        table.add_column("Proto", style="magenta", width=5)
        table.add_column("Location", style="dim", width=15)
        table.add_column("Status", width=12)

        seen_dests = set()
        for flow in (self._selected_flows or []):
            dst_key = f"{flow.dst_ip}:{flow.dst_port}"
            if dst_key in seen_dests:
                continue
            seen_dests.add(dst_key)

            hostname = self._get_hostname(flow.dst_ip) or "-"
            location = self._format_geo_location(flow.dst_geo) if flow.dst_geo else "-"

            # Check trace status
            if flow.dst_ip in self._pending_traces:
                status = "[yellow]Tracing...[/yellow]"
            elif flow.dst_ip in self._traces:
                status = "[green]Traced[/green]"
            else:
                status = "[dim]Pending[/dim]"

            table.add_row(
                flow.dst_ip,
                hostname,
                str(flow.dst_port) if flow.dst_port else "-",
                flow.protocol_name,
                location,
                status,
            )

        return table

    def _render_route_patterns(self, dst_ip: str) -> Optional[Table]:
        """Render route pattern history for a destination."""
        if not self.route_repo:
            return None

        patterns = self.route_repo.get_route_history(
            src_ip="",  # Will use local IP from DBPathTracer
            dst_ip=dst_ip,
            limit=5,
        )
        if not patterns:
            return None

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title=f"[bold]Route History to {dst_ip}[/bold]",
        )

        table.add_column("Hops", justify="center", width=5)
        table.add_column("Path", style="green")
        table.add_column("Seen", justify="right", width=6)
        table.add_column("Avg Latency", justify="right", width=10)
        table.add_column("Status", width=10)

        for pattern in patterns:
            # Show hop path as abbreviated
            path_str = " → ".join(
                ip[:12] + "..." if len(ip) > 15 else ip
                for ip in pattern.hop_ips[:5]
            )
            if len(pattern.hop_ips) > 5:
                path_str += f" (+{len(pattern.hop_ips) - 5} more)"

            latency = f"{pattern.avg_total_latency:.1f}ms" if pattern.avg_total_latency else "-"
            status = "[green]Active[/green]" if pattern.is_stable else "[dim]Historic[/dim]"

            table.add_row(
                str(pattern.hop_count),
                path_str,
                str(pattern.times_seen),
                latency,
                status,
            )

        return table

    def _render_route_changes(self) -> Optional[Table]:
        """Render recent route changes."""
        if not self.route_repo:
            return None

        changes = self.route_repo.get_route_changes(limit=10)
        if not changes:
            return None

        table = Table(
            show_header=True,
            header_style="bold yellow",
            border_style="dim",
            expand=True,
            title="[bold]Recent Route Changes[/bold]",
        )

        table.add_column("Destination", style="cyan", width=16)
        table.add_column("Change", style="yellow", width=12)
        table.add_column("Old Hops", justify="center", width=8)
        table.add_column("New Hops", justify="center", width=8)
        table.add_column("When", width=12)

        import time
        now = time.time()
        for change in changes:
            # Format time ago
            ago = now - change.changed_at
            if ago < 60:
                when = f"{int(ago)}s ago"
            elif ago < 3600:
                when = f"{int(ago / 60)}m ago"
            else:
                when = f"{int(ago / 3600)}h ago"

            change_type = change.change_type or "changed"
            change_style = {
                "new": "[green]new[/green]",
                "hop_added": "[yellow]+hop[/yellow]",
                "hop_removed": "[red]-hop[/red]",
                "hop_changed": "[cyan]reroute[/cyan]",
                "path_shift": "[dim]shift[/dim]",
            }.get(change_type, change_type)

            table.add_row(
                change.dst_ip,
                change_style,
                str(change.old_hop_count) if change.old_hop_count else "-",
                str(change.new_hop_count),
                when,
            )

        return table

    def render(self) -> RenderableType:
        """Render the paths panel."""
        elements = []

        # If we have selected flows, show their paths
        if self._selected_flows:
            elements.append(self._render_flow_paths())

            # Show hop summary for selected flows (filtered by selected IPs)
            elements.append(Text(""))
            elements.append(self._render_hop_summary())

            # Show route patterns for selected destinations
            selected_dests = self._get_selected_destinations()
            for dst_ip in list(selected_dests)[:3]:  # Limit to 3
                pattern_table = self._render_route_patterns(dst_ip)
                if pattern_table:
                    elements.append(Text(""))
                    elements.append(pattern_table)

            # Show route changes if available
            changes_table = self._render_route_changes()
            if changes_table:
                elements.append(Text(""))
                elements.append(changes_table)
        elif self.current_trace:
            # Show current traceroute if active (manual trace)
            elements.append(self._render_traceroute(self.current_trace))
            status = "Complete" if self.current_trace.completed else "In Progress"
            hops = self.current_trace.total_hops
            duration = f"{self.current_trace.duration:.1f}s"
            elements.append(Text(f"[dim]Status: {status} | Hops: {hops} | Duration: {duration}[/dim]"))
            elements.append(Text(""))  # Spacer
            elements.append(self._render_hop_summary())

            # Show route changes if available
            changes_table = self._render_route_changes()
            if changes_table:
                elements.append(Text(""))
                elements.append(changes_table)
        else:
            # Show general hop summary
            elements.append(self._render_hop_summary())

            # Show route changes if available
            changes_table = self._render_route_changes()
            if changes_table:
                elements.append(Text(""))
                elements.append(changes_table)

            elements.append(Text(""))
            elements.append(Text("[dim]Press 't' to run a traceroute, or select flows in Traffic view.[/dim]"))

        return Group(*elements)
