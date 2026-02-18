"""Main dashboard application."""

import os
import time
from typing import Optional
from enum import Enum, auto

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from capture.sniffer import PacketSniffer
from capture.parser import PacketParser
from tracking.db_flow import DBFlowTracker
from tracking.hops import HopAnalyzer
from tracking.path import PathTracer
from tracking.db_path import DBPathTracer
from tracking.classifier import TrafficClassifier
from tracking.db_ports import DBPortTracker
from tracking.dns_tracker import DNSTracker
from geo.resolver import GeoResolver
from geo.dns_resolver import DNSResolver
from geo.ownership import OwnershipResolver
from dashboard.panels.traffic import TrafficPanel
from dashboard.panels.paths import PathsPanel
from dashboard.panels.stats import StatsPanel
from dashboard.panels.analysis import AnalysisPanel, PacketAnalyzer
from dashboard.panels.ports import PortsPanel
from dashboard.panels.dns import DNSPanel
from dashboard.panels.relay import RelayPanel
from dashboard.panels.alerts import AlertsPanel
from dashboard.panels.graph import GraphPanel
from dashboard.panels.dpi import DPIPanel
from security.alerts import AlertEngine
from security.graph import ConnectionGraph
from security.reputation import ReputationChecker
from analysis.dpi import DeepPacketInspector
from dashboard.input_handler import InputHandler, Key, KeyEvent
from config import (
    REFRESH_RATE, DB_PATH, DB_READ_POOL_SIZE, DB_WAL_MODE,
    DB_WRITE_BATCH_SIZE, DB_WRITE_FLUSH_MS,
    ALERTS_ENABLED, REPUTATION_CHECK_ENABLED, REPUTATION_API_KEY,
)
from db import ConnectionPool, DatabaseWriter
from db.repositories import (
    SessionRepository, FlowRepository, PortRepository,
    GeoRepository, DNSRepository, HopRepository, DeviceRepository, RouteRepository,
    DNSQueryRepository, RelayRepository
)
from utils.network import is_private_ip, is_api_traffic, get_local_ip
from utils.logger import logger, log_exception


class ViewMode(Enum):
    TRAFFIC = auto()
    PATHS = auto()
    STATS = auto()
    ANALYSIS = auto()
    PORTS = auto()
    DNS = auto()
    RELAY = auto()
    ALERTS = auto()
    GRAPH = auto()
    DPI = auto()


class InputMode(Enum):
    NORMAL = auto()
    FILTER_IP = auto()
    FILTER_PORT = auto()
    TRACEROUTE = auto()


class Dashboard:
    """Main dashboard application with live updates."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip",
    ):
        self.console = Console()
        self.interface = interface
        self.bpf_filter = bpf_filter

        # Initialize database
        db_path = os.path.expanduser(DB_PATH)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        logger.info(f"Initializing database at {db_path}")

        self.db_pool = ConnectionPool(
            db_path=db_path,
            read_pool_size=DB_READ_POOL_SIZE,
            wal_mode=DB_WAL_MODE
        )
        self.db_pool.initialize()  # This also calls init_schema internally

        self.db_writer = DatabaseWriter(
            pool=self.db_pool,
            batch_size=DB_WRITE_BATCH_SIZE,
            flush_interval=DB_WRITE_FLUSH_MS / 1000.0  # Convert ms to seconds
        )
        self.db_writer.start()

        # Initialize repositories
        self.session_repo = SessionRepository(self.db_pool, self.db_writer)
        self.flow_repo = FlowRepository(self.db_pool, self.db_writer)
        self.port_repo = PortRepository(self.db_pool, self.db_writer)
        self.geo_repo = GeoRepository(self.db_pool, self.db_writer)
        self.dns_repo = DNSRepository(self.db_pool, self.db_writer)
        self.hop_repo = HopRepository(self.db_pool, self.db_writer)
        self.device_repo = DeviceRepository(self.db_pool, self.db_writer)
        self.route_repo = RouteRepository(self.db_pool, self.db_writer)
        self.dns_query_repo = DNSQueryRepository(self.db_pool, self.db_writer)
        self.relay_repo = RelayRepository(self.db_pool, self.db_writer)

        # Create session
        self.session_id = self.session_repo.create_session(
            interface=interface,
            bpf_filter=bpf_filter
        )
        logger.info(f"Created session {self.session_id}")

        # Set session on repositories that need it
        self.flow_repo.set_session(self.session_id)
        self.port_repo.set_session(self.session_id)
        self.hop_repo.set_session(self.session_id)

        # Core components
        self.sniffer = PacketSniffer(interface=interface, bpf_filter=bpf_filter)
        self.parser = PacketParser()

        # Use database-backed trackers
        self.flow_tracker = DBFlowTracker(
            flow_repo=self.flow_repo,
            session_id=self.session_id
        )
        self.port_tracker = DBPortTracker(
            port_repo=self.port_repo
        )

        # DNS tracker
        self.dns_tracker = DNSTracker(
            dns_query_repo=self.dns_query_repo,
            session_id=self.session_id
        )

        self.hop_analyzer = HopAnalyzer()
        self._path_tracer = PathTracer()

        # Resolvers with database persistence (need to create before DBPathTracer)
        self.geo_resolver = GeoResolver(geo_repo=self.geo_repo)
        self.dns_resolver = DNSResolver(dns_repo=self.dns_repo)
        self.ownership_resolver = OwnershipResolver()

        # Database-backed path tracer
        self.path_tracer = DBPathTracer(
            path_tracer=self._path_tracer,
            hop_repo=self.hop_repo,
            route_repo=self.route_repo,
            geo_resolver=self.geo_resolver,
            dns_resolver=self.dns_resolver,
        )

        # Set local IP for route tracking
        local_ip = get_local_ip()
        if local_ip:
            self.path_tracer.set_local_ip(local_ip)
            logger.info(f"Local IP for route tracking: {local_ip}")

        self.packet_analyzer = PacketAnalyzer()
        self.classifier = TrafficClassifier()

        # Security components
        self.alert_engine = AlertEngine() if ALERTS_ENABLED else None
        self.connection_graph = ConnectionGraph()
        self.reputation_checker = ReputationChecker(
            api_key=REPUTATION_API_KEY
        ) if REPUTATION_CHECK_ENABLED and REPUTATION_API_KEY else None

        # Deep packet inspection
        self.dpi = DeepPacketInspector(max_packets_per_flow=100)

        # Panels
        self.traffic_panel = TrafficPanel(self.flow_tracker, self.dns_resolver)
        self.paths_panel = PathsPanel(
            self.path_tracer,
            self.hop_analyzer,
            self.geo_resolver,
            self.dns_resolver,
            self.ownership_resolver,
            hop_repo=self.hop_repo,
            route_repo=self.route_repo,
        )
        self.stats_panel = StatsPanel(self.flow_tracker, self.geo_resolver, self.dns_resolver, self.dns_tracker)
        self.analysis_panel = AnalysisPanel(self.packet_analyzer, self.classifier)
        self.ports_panel = PortsPanel(self.port_tracker)
        self.dns_panel = DNSPanel(self.dns_tracker)
        self.relay_panel = RelayPanel(self.relay_repo)
        self.alerts_panel = AlertsPanel(self.alert_engine) if self.alert_engine else None
        self.graph_panel = GraphPanel(self.connection_graph)
        self.dpi_panel = DPIPanel(self.dpi)

        # State
        self.view_mode = ViewMode.TRAFFIC
        self.input_mode = InputMode.NORMAL
        self.paused = False
        self.running = False
        self._packet_count = 0

        # Input handling
        self.input_handler = InputHandler()
        self.input_buffer = ""
        self.status_message = ""
        self.status_timeout = 0

    def _create_layout(self) -> Layout:
        """Create the dashboard layout."""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3),
        )

        return layout

    def _render_header(self) -> Panel:
        """Render the header panel."""
        iface = self.interface or "auto"
        status = "[yellow]PAUSED[/yellow]" if self.paused else "[green]CAPTURING[/green]"
        mode_names = {
            ViewMode.TRAFFIC: "[bold cyan]Traffic[/bold cyan]",
            ViewMode.PATHS: "[bold cyan]Paths[/bold cyan]",
            ViewMode.STATS: "[bold cyan]Stats[/bold cyan]",
            ViewMode.ANALYSIS: "[bold cyan]Analysis[/bold cyan]",
            ViewMode.PORTS: "[bold cyan]Ports[/bold cyan]",
            ViewMode.DNS: "[bold cyan]DNS[/bold cyan]",
            ViewMode.RELAY: "[bold cyan]Relay[/bold cyan]",
            ViewMode.ALERTS: "[bold red]Alerts[/bold red]",
            ViewMode.GRAPH: "[bold magenta]Graph[/bold magenta]",
            ViewMode.DPI: "[bold yellow]DPI[/bold yellow]",
        }
        current_mode = mode_names[self.view_mode]

        title = f"[bold]PacketTracer[/bold] | Interface: {iface} | Status: {status} | View: {current_mode}"

        # Add filter info for traffic view
        if self.view_mode == ViewMode.TRAFFIC:
            filters = []
            if self.traffic_panel.filter_protocol:
                filters.append(f"proto={self.traffic_panel.filter_protocol}")
            if self.traffic_panel.filter_ip:
                filters.append(f"ip={self.traffic_panel.filter_ip}")
            if self.traffic_panel.filter_port:
                filters.append(f"port={self.traffic_panel.filter_port}")
            if filters:
                title += f" | [dim]Filters: {', '.join(filters)}[/dim]"

        return Panel(Text.from_markup(title), style="bold white on blue")

    def _render_footer(self) -> Panel:
        """Render the footer with controls."""
        # Check for input mode
        if self.input_mode == InputMode.FILTER_IP:
            content = f"[bold]Filter by IP:[/bold] {self.input_buffer}█  [dim](Enter=apply, Esc=cancel)[/dim]"
            return Panel(Text.from_markup(content), style="yellow")

        if self.input_mode == InputMode.FILTER_PORT:
            content = f"[bold]Filter by Port:[/bold] {self.input_buffer}█  [dim](Enter=apply, Esc=cancel)[/dim]"
            return Panel(Text.from_markup(content), style="yellow")

        if self.input_mode == InputMode.TRACEROUTE:
            content = f"[bold]Traceroute to:[/bold] {self.input_buffer}█  [dim](Enter=start, Esc=cancel)[/dim]"
            return Panel(Text.from_markup(content), style="yellow")

        # Check for status message
        if self.status_message and time.time() < self.status_timeout:
            return Panel(Text.from_markup(self.status_message), style="dim")

        # Show selected flows info if any
        selected_flows = self.traffic_panel.get_selected_flows()
        if selected_flows and self.view_mode in (ViewMode.PATHS, ViewMode.STATS, ViewMode.ANALYSIS, ViewMode.PORTS):
            # Show what we're filtering by
            ips = set()
            for f in selected_flows[:5]:  # Show up to 5 IPs
                ips.add(f.dst_ip)
            ip_list = ", ".join(list(ips)[:3])
            if len(ips) > 3:
                ip_list += f" +{len(ips)-3} more"
            return Panel(
                Text.from_markup(f"[yellow]Showing stats for {len(selected_flows)} selected flow(s): {ip_list}[/yellow]  |  [dim]Press [bold]c[/bold] in Traffic view to clear selection[/dim]"),
                style="yellow",
            )

        # Normal controls based on view
        if self.view_mode == ViewMode.TRAFFIC:
            controls = [
                "[bold]↑↓[/bold]=Nav",
                "[bold]Space[/bold]=Select",
                "[bold]a[/bold]=All",
                "[bold]g[/bold]=Group",
                "[bold]c[/bold]=Clear",
                "[bold]/[/bold]=Filter",
                "[bold]s[/bold]=Sort",
                "[bold]Enter[/bold]=Trace",
            ]
        elif self.view_mode == ViewMode.PATHS:
            controls = [
                "[bold]s[/bold]=Trace selected",
                "[bold]r[/bold]=Refresh",
                "[bold]c[/bold]=Clear",
            ]
        elif self.view_mode == ViewMode.PORTS:
            controls = [
                "[bold]s[/bold]=Sort mode",
            ]
        elif self.view_mode == ViewMode.STATS:
            controls = []  # Stats is display-only
        elif self.view_mode == ViewMode.ANALYSIS:
            controls = []  # Analysis is display-only
        elif self.view_mode == ViewMode.DNS:
            controls = [
                "[bold]v[/bold]=View mode",
                "[bold]r[/bold]=Responses only",
                "[bold]n[/bold]=NXDOMAIN only",
            ]
        elif self.view_mode == ViewMode.RELAY:
            if self.relay_panel.is_in_input_mode():
                controls = [
                    "[bold]Tab[/bold]=Next",
                    "[bold]Enter[/bold]=Submit",
                    "[bold]Esc[/bold]=Cancel",
                ]
            else:
                controls = [
                    "[bold]d[/bold]=Deploy",
                    "[bold]n[/bold]=Register",
                    "[bold]1-9[/bold]=Select",
                    "[bold]r[/bold]=Refresh",
                ]
        elif self.view_mode == ViewMode.ALERTS:
            controls = [
                "[bold]↑↓[/bold]=Nav",
                "[bold]Enter[/bold]=Ack",
                "[bold]A[/bold]=Ack all",
                "[bold]f[/bold]=Filter sev",
                "[bold]a[/bold]=Show ack'd",
            ]
        elif self.view_mode == ViewMode.GRAPH:
            controls = [
                "[bold]v[/bold]=View mode",
            ]
        elif self.view_mode == ViewMode.DPI:
            controls = [
                "[bold]v[/bold]=View mode",
                "[bold]←→[/bold]=Prev/Next pkt",
                "[bold]↑↓[/bold]=Scroll",
                "[bold]c[/bold]=Clear",
            ]
        else:
            controls = []

        # Global controls
        global_controls = [
            "[bold]0-9[/bold]=Views",
            "[bold]p[/bold]=Pause",
            "[bold]t[/bold]=Trace",
            "[bold]q[/bold]=Quit",
        ]

        all_controls = controls + global_controls if controls else global_controls
        return Panel(
            Text.from_markup("  ".join(all_controls)),
            style="dim",
        )

    def _render_main(self) -> Panel:
        """Render the main panel based on current view mode."""
        # Get selected flows if any
        selected_flows = self.traffic_panel.get_selected_flows()
        if not selected_flows:
            selected_flows = None

        if self.view_mode == ViewMode.TRAFFIC:
            content = self.traffic_panel.render()
        elif self.view_mode == ViewMode.PATHS:
            # Pass selected flows to paths panel for hop summary filtering
            self.paths_panel.set_selected_flows(selected_flows)
            content = self.paths_panel.render()
        elif self.view_mode == ViewMode.STATS:
            # Pass selected flows to stats panel
            self.stats_panel.set_selected_flows(selected_flows)
            content = self.stats_panel.render()
        elif self.view_mode == ViewMode.ANALYSIS:
            # Pass selected flows to analysis panel
            self.analysis_panel.set_selected_flows(selected_flows)
            content = self.analysis_panel.render()
        elif self.view_mode == ViewMode.PORTS:
            self.ports_panel.set_selected_flows(selected_flows)
            content = self.ports_panel.render()
        elif self.view_mode == ViewMode.DNS:
            content = self.dns_panel.render()
        elif self.view_mode == ViewMode.RELAY:
            content = self.relay_panel.render()
        elif self.view_mode == ViewMode.ALERTS:
            if self.alerts_panel:
                content = self.alerts_panel.render()
            else:
                from rich.text import Text
                content = Text("[dim]Alerting is disabled. Set ALERTS_ENABLED=True in config.[/dim]")
        elif self.view_mode == ViewMode.GRAPH:
            content = self.graph_panel.render()
        else:  # DPI
            # Pass selected flows to DPI panel
            self.dpi_panel.set_selected_flows(selected_flows)
            content = self.dpi_panel.render()

        return Panel(content, border_style="dim")

    def _show_status(self, message: str, duration: float = 2.0) -> None:
        """Show a status message temporarily."""
        self.status_message = message
        self.status_timeout = time.time() + duration

    def _packet_callback(self, packet) -> None:
        """Handle incoming packets."""
        if self.paused:
            return

        parsed = self.parser.parse(packet)
        if not parsed:
            return

        # Filter out our own API traffic (ip-api.com lookups)
        if is_api_traffic(parsed.src_ip) or is_api_traffic(parsed.dst_ip):
            return

        self._packet_count += 1

        # Update flow tracker (database-backed)
        flow = self.flow_tracker.process_packet(parsed)

        # Update session stats
        self.session_repo.increment_stats(self.session_id, 1, parsed.length)

        # Record TTL for hop analysis
        self.hop_analyzer.record_ttl(parsed.src_ip, parsed.ttl)

        # Packet analysis
        self.packet_analyzer.process_packet(parsed)

        # Traffic classification
        self.classifier.classify_flow(flow)

        # Port tracking (database-backed)
        self.port_tracker.record_packet(
            src_port=parsed.src_port,
            dst_port=parsed.dst_port,
            protocol=parsed.protocol_name,
            length=parsed.length,
            src_ip=parsed.src_ip,
            dst_ip=parsed.dst_ip,
        )

        # DNS tracking (database-backed)
        if parsed.dns:
            self.dns_tracker.process_packet(parsed)

        # Update connection graph
        if flow:
            self.connection_graph.add_flow(flow)

        # Check for security alerts
        if self.alert_engine and flow:
            self.alert_engine.check_flow(flow)

        # Deep packet inspection for targeted flows
        if flow and self.dpi.is_target(flow.flow_key):
            self.dpi.process_packet(packet, flow.flow_key)

        # Get flow key for database updates
        flow_key = flow.flow_key if flow else None

        # Queue geo and DNS lookup for non-private IPs with callbacks
        if not is_private_ip(parsed.dst_ip):
            # Geo resolution with callback to update flow
            def on_geo_resolved(geo, ip=parsed.dst_ip, fk=flow_key):
                if geo and fk:
                    geo_dict = {
                        "country": geo.country if hasattr(geo, 'country') else geo.get("country"),
                        "country_code": geo.country_code if hasattr(geo, 'country_code') else geo.get("country_code"),
                        "city": geo.city if hasattr(geo, 'city') else geo.get("city"),
                        "isp": geo.isp if hasattr(geo, 'isp') else geo.get("isp"),
                        "as_name": geo.as_name if hasattr(geo, 'as_name') else geo.get("as_name"),
                    }
                    self.flow_repo.update_geo_data(fk, geo_dict, is_destination=True)
                if flow:
                    flow.dst_geo = geo

            # DNS resolution with callback to update flow
            def on_dns_resolved(host_info, ip=parsed.dst_ip, fk=flow_key):
                if host_info and fk:
                    self.flow_repo.update_dns_data(
                        fk,
                        hostname=host_info.hostname,
                        domain=host_info.domain,
                        fqdn=host_info.fqdn,
                        is_destination=True
                    )

            self.geo_resolver.resolve_async(parsed.dst_ip, callback=on_geo_resolved)
            self.dns_resolver.resolve_async(parsed.dst_ip, callback=on_dns_resolved)

        if not is_private_ip(parsed.src_ip):
            def on_src_geo_resolved(geo, ip=parsed.src_ip, fk=flow_key):
                if geo and fk:
                    geo_dict = {
                        "country": geo.country if hasattr(geo, 'country') else geo.get("country"),
                        "city": geo.city if hasattr(geo, 'city') else geo.get("city"),
                        "isp": geo.isp if hasattr(geo, 'isp') else geo.get("isp"),
                    }
                    self.flow_repo.update_geo_data(fk, geo_dict, is_destination=False)
                if flow:
                    flow.src_geo = geo

            self.geo_resolver.resolve_async(parsed.src_ip, callback=on_src_geo_resolved)
            self.dns_resolver.resolve_async(parsed.src_ip)

    def _handle_input_mode(self, event: KeyEvent) -> bool:
        """Handle input during input mode. Returns True if still in input mode."""
        if event.key == Key.ESCAPE:
            self.input_mode = InputMode.NORMAL
            self.input_buffer = ""
            return False

        if event.key == Key.ENTER:
            self._apply_input()
            self.input_mode = InputMode.NORMAL
            self.input_buffer = ""
            return False

        if event.key == Key.BACKSPACE:
            self.input_buffer = self.input_buffer[:-1]
            return True

        if event.char and event.char.isprintable():
            self.input_buffer += event.char
            return True

        return True

    def _apply_input(self) -> None:
        """Apply the current input buffer based on input mode."""
        if self.input_mode == InputMode.FILTER_IP:
            self.traffic_panel.set_ip_filter(self.input_buffer)
            self._show_status(f"[green]IP filter set: {self.input_buffer}[/green]")

        elif self.input_mode == InputMode.FILTER_PORT:
            try:
                port = int(self.input_buffer) if self.input_buffer else None
                self.traffic_panel.set_port_filter(port)
                self._show_status(f"[green]Port filter set: {port}[/green]")
            except ValueError:
                self._show_status("[red]Invalid port number[/red]")

        elif self.input_mode == InputMode.TRACEROUTE:
            if self.input_buffer:
                self.traceroute(self.input_buffer)
                self._show_status(f"[green]Traceroute started to {self.input_buffer}[/green]")

    def _handle_normal_input(self, event: KeyEvent) -> bool:
        """Handle normal mode input. Returns False to quit."""
        # IMPORTANT: Check relay panel input mode FIRST before any hotkeys
        if self.view_mode == ViewMode.RELAY and self.relay_panel.is_in_input_mode():
            if event.key == Key.ESCAPE:
                self.relay_panel.handle_special_key("escape")
                return True
            elif event.key == Key.ENTER:
                self.relay_panel.handle_special_key("enter")
                return True
            elif event.key == Key.BACKSPACE:
                self.relay_panel.handle_special_key("backspace")
                return True
            elif event.key == Key.TAB:
                self.relay_panel.handle_special_key("tab")
                return True
            elif event.char and event.char.isprintable():
                self.relay_panel.handle_key(event.char)
                return True
            # Ignore other keys in input mode
            return True

        # Quit
        if event.char == "q":
            return False

        # View switching
        elif event.char == "1":
            self.view_mode = ViewMode.TRAFFIC
        elif event.char == "2":
            self.view_mode = ViewMode.PATHS
        elif event.char == "3":
            self.view_mode = ViewMode.STATS
        elif event.char == "4":
            self.view_mode = ViewMode.ANALYSIS
        elif event.char == "5":
            self.view_mode = ViewMode.PORTS
        elif event.char == "6":
            self.view_mode = ViewMode.DNS
        elif event.char == "7":
            self.view_mode = ViewMode.RELAY
        elif event.char == "8":
            self.view_mode = ViewMode.ALERTS
        elif event.char == "9":
            self.view_mode = ViewMode.GRAPH
        elif event.char == "0":
            self.view_mode = ViewMode.DPI

        # Pause
        elif event.char == "p":
            self.paused = not self.paused
            status = "paused" if self.paused else "resumed"
            self._show_status(f"[yellow]Capture {status}[/yellow]")

        # Sort (traffic view)
        elif event.char == "s" and self.view_mode == ViewMode.TRAFFIC:
            new_sort = self.traffic_panel.cycle_sort()
            self._show_status(f"[cyan]Sorting by {new_sort}[/cyan]")

        # Protocol filter (traffic view)
        elif event.char == "f" and self.view_mode == ViewMode.TRAFFIC:
            proto = self.traffic_panel.cycle_protocol_filter()
            msg = f"Protocol filter: {proto}" if proto else "Protocol filter: All"
            self._show_status(f"[cyan]{msg}[/cyan]")

        # IP filter
        elif event.char == "/" and self.view_mode == ViewMode.TRAFFIC:
            self.input_mode = InputMode.FILTER_IP
            self.input_buffer = ""

        # Port filter
        elif event.char == ":" and self.view_mode == ViewMode.TRAFFIC:
            self.input_mode = InputMode.FILTER_PORT
            self.input_buffer = ""

        # Clear filters
        elif event.char == "c" and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.clear_filters()
            self.traffic_panel.clear_selection()
            self._show_status("[cyan]Filters cleared[/cyan]")

        # Traceroute
        elif event.char == "t":
            self.input_mode = InputMode.TRACEROUTE
            self.input_buffer = ""
            # Pre-fill with selected flow's destination if available
            if self.view_mode == ViewMode.TRAFFIC:
                flow = self.traffic_panel.get_current_flow()
                if flow:
                    self.input_buffer = flow.dst_ip

        # Toggle local traffic
        elif event.char == "l" and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.toggle_local()
            status = "shown" if self.traffic_panel.show_local else "hidden"
            self._show_status(f"[cyan]Local traffic {status}[/cyan]")

        # Toggle between flows and destinations view
        elif event.char == "g" and self.view_mode == ViewMode.TRAFFIC:
            mode = self.traffic_panel.toggle_view_mode()
            if mode == "destinations":
                self._show_status("[cyan]Grouped by destination[/cyan]")
            else:
                self._show_status("[cyan]Showing individual flows[/cyan]")

        # Navigation (traffic view)
        elif event.key == Key.UP and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.move_up()
        elif event.key == Key.DOWN and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.move_down()
        elif event.key == Key.PAGE_UP and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.page_up()
        elif event.key == Key.PAGE_DOWN and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.page_down()
        elif event.key == Key.HOME and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.home()
        elif event.key == Key.END and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.end()

        # Selection
        elif event.key == Key.SPACE and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.toggle_selection()
            count = len(self.traffic_panel.selected_keys)
            self._show_status(f"[cyan]Selected: {count} flows[/cyan]", 1.0)

        # Select all
        elif event.char == "a" and self.view_mode == ViewMode.TRAFFIC:
            self.traffic_panel.select_all()
            count = len(self.traffic_panel.selected_keys)
            self._show_status(f"[cyan]Selected all: {count} flows[/cyan]")

        # Enter - show details or trace selected
        elif event.key == Key.ENTER and self.view_mode == ViewMode.TRAFFIC:
            flow = self.traffic_panel.get_current_flow()
            if flow:
                self.traceroute(flow.dst_ip)
                self.view_mode = ViewMode.PATHS

        # Paths panel controls
        elif event.char == "s" and self.view_mode == ViewMode.PATHS:
            # Start tracing selected flow destinations
            count = self.paths_panel.trace_selected_flows()
            if count > 0:
                self._show_status(f"[cyan]Starting {count} trace(s)...[/cyan]")
            else:
                self._show_status("[dim]No new destinations to trace[/dim]")

        elif event.char == "r" and self.view_mode == ViewMode.PATHS:
            count = self.paths_panel.refresh_traces()
            if count > 0:
                self._show_status(f"[cyan]Refreshing {count} trace(s)...[/cyan]")
            else:
                self._show_status("[dim]No traces to refresh[/dim]")

        elif event.char == "c" and self.view_mode == ViewMode.PATHS:
            self.paths_panel.clear_traces()
            self._show_status("[cyan]Traces cleared[/cyan]")

        # DNS panel controls
        elif event.char == "v" and self.view_mode == ViewMode.DNS:
            new_view = self.dns_panel.cycle_view()
            self._show_status(f"[cyan]DNS view: {new_view}[/cyan]")

        elif event.char == "r" and self.view_mode == ViewMode.DNS:
            responses_only = self.dns_panel.toggle_responses_only()
            status = "on" if responses_only else "off"
            self._show_status(f"[cyan]Responses only: {status}[/cyan]")

        elif event.char == "n" and self.view_mode == ViewMode.DNS:
            nxdomain_only = self.dns_panel.toggle_nxdomain_only()
            status = "on" if nxdomain_only else "off"
            self._show_status(f"[cyan]NXDOMAIN only: {status}[/cyan]")

        # Sort for ports panel
        elif event.char == "s" and self.view_mode == ViewMode.PORTS:
            new_sort = self.ports_panel.cycle_sort()
            self._show_status(f"[cyan]Port sort: {new_sort}[/cyan]")

        # Relay panel controls (normal mode only - input mode handled at top)
        elif self.view_mode == ViewMode.RELAY:
            if event.char:
                self.relay_panel.handle_key(event.char)
            elif event.key == Key.ESCAPE:
                self.relay_panel.handle_special_key("escape")
            elif event.key == Key.DELETE:
                self.relay_panel.handle_special_key("delete")

        # Alerts panel controls
        elif self.view_mode == ViewMode.ALERTS and self.alerts_panel:
            if event.key == Key.UP:
                self.alerts_panel.move_up()
            elif event.key == Key.DOWN:
                self.alerts_panel.move_down()
            elif event.key == Key.ENTER:
                if self.alerts_panel.acknowledge_selected():
                    self._show_status("[green]Alert acknowledged[/green]")
            elif event.char == "A":  # Shift+A for ack all
                count = self.alerts_panel.acknowledge_all()
                self._show_status(f"[green]Acknowledged {count} alerts[/green]")
            elif event.char == "a":  # Toggle showing acknowledged
                show = self.alerts_panel.toggle_acknowledged()
                status = "showing" if show else "hiding"
                self._show_status(f"[cyan]{status.title()} acknowledged alerts[/cyan]")
            elif event.char == "f":  # Filter severity
                sev = self.alerts_panel.cycle_severity_filter()
                if sev:
                    self._show_status(f"[cyan]Filtering: {sev}[/cyan]")
                else:
                    self._show_status("[cyan]Showing all severities[/cyan]")

        # Graph panel controls
        elif self.view_mode == ViewMode.GRAPH:
            if event.char == "v":
                mode = self.graph_panel.cycle_view_mode()
                self._show_status(f"[cyan]Graph view: {mode}[/cyan]")

        # DPI panel controls
        elif self.view_mode == ViewMode.DPI:
            if event.char == "v":
                mode = self.dpi_panel.cycle_view_mode()
                self._show_status(f"[cyan]DPI view: {mode}[/cyan]")
            elif event.key == Key.LEFT:
                self.dpi_panel.prev_packet()
            elif event.key == Key.RIGHT:
                self.dpi_panel.next_packet()
            elif event.key == Key.UP:
                self.dpi_panel.scroll_up()
            elif event.key == Key.DOWN:
                self.dpi_panel.scroll_down()
            elif event.char == "c":
                self.dpi_panel.clear_inspection()
                self._show_status("[cyan]DPI inspection cleared[/cyan]")

        return True

    def _handle_input(self, event: KeyEvent) -> bool:
        """Handle keyboard input. Returns False to quit."""
        if self.input_mode != InputMode.NORMAL:
            self._handle_input_mode(event)
            return True
        return self._handle_normal_input(event)

    def run(self) -> None:
        """Run the dashboard without input handling (simple mode)."""
        self.running = True

        # Start background services
        self.sniffer.callback = self._packet_callback
        self.sniffer.start()
        self.geo_resolver.start_background_resolver()
        self.dns_resolver.start()

        layout = self._create_layout()

        try:
            with Live(
                layout,
                console=self.console,
                refresh_per_second=int(1 / REFRESH_RATE),
                screen=True,
            ) as _live:  # noqa: F841 - context manager
                while self.running:
                    layout["header"].update(self._render_header())
                    layout["main"].update(self._render_main())
                    layout["footer"].update(self._render_footer())
                    time.sleep(REFRESH_RATE)

        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def run_with_input(self) -> None:
        """Run dashboard with keyboard input handling."""
        logger.info("Starting dashboard with input handling")
        self.running = True

        # Start background services
        self.sniffer.callback = self._packet_callback
        self.sniffer.start()
        self.geo_resolver.start_background_resolver()
        self.dns_resolver.start()
        logger.info("Background services started")

        layout = self._create_layout()

        try:
            logger.info("Entering input handler context")
            with self.input_handler:
                logger.info("Input handler started, entering Live context")
                with Live(
                    layout,
                    console=self.console,
                    refresh_per_second=int(1 / REFRESH_RATE),
                    screen=True,
                ) as _live:  # noqa: F841 - context manager
                    logger.info("Live display started, entering main loop")
                    while self.running:
                        try:
                            # Process ALL pending key events for responsive input
                            events = self.input_handler.get_all_keys()
                            if events:
                                logger.debug(f"Got {len(events)} key events")
                            for event in events:
                                logger.debug(f"Processing key event: char={repr(event.char)}, key={event.key}")
                                try:
                                    if not self._handle_input(event):
                                        logger.info("Quit requested via input")
                                        self.running = False
                                        break
                                except Exception as e:
                                    logger.error(f"Error handling input: {e}")
                                    log_exception("Input handling error")

                            if not self.running:
                                break

                            # Update layout
                            try:
                                layout["header"].update(self._render_header())
                            except Exception as e:
                                logger.error(f"Error rendering header: {e}")
                                log_exception("Header render error")

                            try:
                                layout["main"].update(self._render_main())
                            except Exception as e:
                                logger.error(f"Error rendering main: {e}")
                                log_exception("Main render error")

                            try:
                                layout["footer"].update(self._render_footer())
                            except Exception as e:
                                logger.error(f"Error rendering footer: {e}")
                                log_exception("Footer render error")

                            # Short sleep for CPU efficiency
                            time.sleep(0.05)

                        except Exception as e:
                            logger.error(f"Error in main loop iteration: {e}")
                            log_exception("Main loop error")

        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        except Exception as e:
            logger.error(f"Fatal error in run_with_input: {e}")
            log_exception("Fatal error")
            raise
        finally:
            logger.info("Stopping dashboard")
            self.stop()

    def stop(self) -> None:
        """Stop the dashboard and cleanup."""
        self.running = False
        self.sniffer.stop()
        self.geo_resolver.stop_background_resolver()
        self.dns_resolver.stop()

        # Stop reputation checker if running
        if hasattr(self, 'reputation_checker') and self.reputation_checker:
            self.reputation_checker.stop()

        # End session and cleanup database
        if hasattr(self, 'session_id') and self.session_id:
            logger.info(f"Ending session {self.session_id}")
            self.session_repo.end_session(self.session_id)

        if hasattr(self, 'db_writer'):
            logger.info("Stopping database writer")
            self.db_writer.stop()

        if hasattr(self, 'db_pool'):
            logger.info("Closing database connections")
            self.db_pool.close()

    def traceroute(self, target: str) -> None:
        """Start a traceroute to the target."""
        self.paths_panel.start_trace(target)
        self.view_mode = ViewMode.PATHS
