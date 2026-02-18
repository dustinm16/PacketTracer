"""Deep Packet Inspection panel for detailed flow analysis."""

from typing import Optional, List
from datetime import datetime

from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType

from analysis.dpi import DeepPacketInspector, FlowInspection
from tracking.flow import Flow
from utils.network import format_bytes


class DPIViewMode:
    """DPI view modes."""
    OVERVIEW = "overview"
    PACKETS = "packets"
    HEX_DUMP = "hex"
    PAYLOAD = "payload"
    ANALYSIS = "analysis"


class DPIPanel:
    """Panel for deep packet inspection display."""

    def __init__(self, dpi: DeepPacketInspector):
        self.dpi = dpi
        self.view_mode = DPIViewMode.OVERVIEW
        self.selected_packet_index = 0
        self._selected_flows: Optional[List[Flow]] = None
        self._active_flow_key: Optional[str] = None
        self.scroll_offset = 0
        self.max_hex_lines = 20

    def set_selected_flows(self, flows: Optional[List[Flow]]) -> None:
        """Set selected flows for inspection."""
        self._selected_flows = flows
        if flows and len(flows) > 0:
            flow = flows[0]
            self._active_flow_key = flow.flow_key
            # Add as inspection target
            self.dpi.add_target(flow.flow_key)

    def get_active_flow_key(self) -> Optional[str]:
        """Get the active flow key being inspected."""
        return self._active_flow_key

    def cycle_view_mode(self) -> str:
        """Cycle through view modes."""
        modes = [
            DPIViewMode.OVERVIEW,
            DPIViewMode.PACKETS,
            DPIViewMode.HEX_DUMP,
            DPIViewMode.PAYLOAD,
            DPIViewMode.ANALYSIS,
        ]
        current_idx = modes.index(self.view_mode)
        next_idx = (current_idx + 1) % len(modes)
        self.view_mode = modes[next_idx]
        return self.view_mode

    def next_packet(self) -> None:
        """Select next packet."""
        if not self._active_flow_key:
            return
        inspection = self.dpi.get_inspection(self._active_flow_key)
        if inspection and self.selected_packet_index < len(inspection.packets) - 1:
            self.selected_packet_index += 1

    def prev_packet(self) -> None:
        """Select previous packet."""
        if self.selected_packet_index > 0:
            self.selected_packet_index -= 1

    def scroll_down(self) -> None:
        """Scroll hex view down."""
        self.scroll_offset += 5

    def scroll_up(self) -> None:
        """Scroll hex view up."""
        if self.scroll_offset > 0:
            self.scroll_offset = max(0, self.scroll_offset - 5)

    def clear_inspection(self) -> None:
        """Clear current inspection."""
        if self._active_flow_key:
            self.dpi.clear_inspection(self._active_flow_key)
            self.dpi.remove_target(self._active_flow_key)
        self._active_flow_key = None
        self.selected_packet_index = 0

    def _format_timestamp(self, ts: float) -> str:
        """Format timestamp."""
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]

    def _render_no_selection(self) -> Panel:
        """Render when no flow is selected."""
        lines = [
            "[bold yellow]No flow selected for inspection[/bold yellow]",
            "",
            "[dim]To inspect a flow:[/dim]",
            "  1. Go to Traffic view (press 1)",
            "  2. Navigate to a flow with arrow keys",
            "  3. Select the flow with Space",
            "  4. Return to DPI view (press 0)",
            "",
            "[dim]Selected flows will be captured for deep inspection.[/dim]",
        ]
        return Panel("\n".join(lines), title="[bold]Deep Packet Inspection[/bold]", border_style="yellow")

    def _render_overview(self, inspection: FlowInspection) -> Panel:
        """Render overview of the inspection."""
        lines = []

        # Flow info
        lines.append(f"[bold cyan]Flow:[/bold cyan] {inspection.src_ip}:{inspection.src_port} -> {inspection.dst_ip}:{inspection.dst_port}")
        lines.append(f"[bold cyan]Protocol:[/bold cyan] {inspection.protocol}")
        lines.append("")

        # Statistics
        lines.append("[bold]Statistics:[/bold]")
        lines.append(f"  Total Packets: {inspection.total_packets}")
        lines.append(f"  Total Bytes:   {format_bytes(inspection.total_bytes)}")
        lines.append(f"  Sent:          {inspection.packets_sent} pkts / {format_bytes(inspection.bytes_sent)}")
        lines.append(f"  Received:      {inspection.packets_recv} pkts / {format_bytes(inspection.bytes_recv)}")
        lines.append(f"  Duration:      {inspection.duration:.2f}s")
        lines.append("")

        # Fingerprinting
        if inspection.src_fingerprint:
            fp = inspection.src_fingerprint
            lines.append(f"[bold]Source OS Fingerprint:[/bold]")
            lines.append(f"  OS Family:     [green]{fp.os_family.value}[/green]")
            lines.append(f"  Confidence:    {fp.confidence:.0%}")
            lines.append(f"  Initial TTL:   {fp.initial_ttl}")
            lines.append("")

        if inspection.dst_fingerprint:
            fp = inspection.dst_fingerprint
            lines.append(f"[bold]Destination OS Fingerprint:[/bold]")
            lines.append(f"  OS Family:     [green]{fp.os_family.value}[/green]")
            lines.append(f"  Confidence:    {fp.confidence:.0%}")
            lines.append("")

        # Application detection
        if inspection.application:
            app = inspection.application
            lines.append(f"[bold]Application Detection:[/bold]")
            lines.append(f"  Protocol:      [magenta]{app.protocol}[/magenta] {app.version}")
            lines.append(f"  Confidence:    {app.confidence:.0%}")

            if app.sni_hostname:
                lines.append(f"  TLS SNI:       {app.sni_hostname}")
            if app.http_host:
                lines.append(f"  HTTP Host:     {app.http_host}")
            if app.http_method:
                lines.append(f"  HTTP Method:   {app.http_method} {app.http_path}")
            if app.user_agent:
                ua = app.user_agent[:60] + "..." if len(app.user_agent) > 60 else app.user_agent
                lines.append(f"  User-Agent:    {ua}")
            if app.ssh_version:
                lines.append(f"  SSH Version:   {app.ssh_version}")
            lines.append("")

        # Flags
        flags = []
        if inspection.is_encrypted:
            flags.append("[green]ENCRYPTED[/green]")
        if inspection.has_payload:
            flags.append("[cyan]HAS_PAYLOAD[/cyan]")

        if flags:
            lines.append(f"[bold]Flags:[/bold] {' '.join(flags)}")

        return Panel("\n".join(lines), title="[bold]Overview[/bold]", border_style="blue")

    def _render_packets_list(self, inspection: FlowInspection) -> Panel:
        """Render list of captured packets."""
        if not inspection.packets:
            return Panel("[dim]No packets captured yet[/dim]", title="[bold]Packets[/bold]", border_style="blue")

        table = Table(show_header=True, header_style="bold", box=None, expand=True)
        table.add_column("#", width=4, justify="right")
        table.add_column("Time", width=12)
        table.add_column("Dir", width=4)
        table.add_column("Src", width=21)
        table.add_column("Dst", width=21)
        table.add_column("Len", width=6, justify="right")
        table.add_column("Flags", width=8)
        table.add_column("Info", ratio=1)

        for i, pkt in enumerate(inspection.packets[:50]):
            is_selected = i == self.selected_packet_index

            # Direction indicator
            if pkt.direction == "send":
                dir_str = "[cyan]>>>[/cyan]"
            else:
                dir_str = "[green]<<<[/green]"

            # Format addresses
            src = f"{pkt.src_ip}:{pkt.src_port}"
            dst = f"{pkt.dst_ip}:{pkt.dst_port}"

            # Info string
            info = ""
            if pkt.flags:
                info = f"[{pkt.flags}]"
            if pkt.payload:
                preview = pkt.payload_ascii[:30]
                if len(pkt.payload_ascii) > 30:
                    preview += "..."
                info += f" {preview}"

            time_str = self._format_timestamp(pkt.timestamp)

            row_style = "reverse" if is_selected else ""

            table.add_row(
                str(i),
                time_str,
                dir_str,
                src[:21],
                dst[:21],
                str(pkt.length),
                pkt.flags,
                info[:50],
                style=row_style,
            )

        title = f"[bold]Packets[/bold] ({len(inspection.packets)} captured, viewing #{self.selected_packet_index})"
        return Panel(table, title=title, border_style="blue")

    def _render_hex_dump(self, inspection: FlowInspection) -> Panel:
        """Render hex dump of selected packet."""
        if not inspection.packets:
            return Panel("[dim]No packets captured[/dim]", title="[bold]Hex Dump[/bold]", border_style="blue")

        if self.selected_packet_index >= len(inspection.packets):
            self.selected_packet_index = len(inspection.packets) - 1

        pkt = inspection.packets[self.selected_packet_index]

        lines = []
        lines.append(f"[bold]Packet #{self.selected_packet_index}[/bold] - {self._format_timestamp(pkt.timestamp)}")
        lines.append(f"Direction: {pkt.direction} | Length: {pkt.length} bytes | TTL: {pkt.ttl}")
        lines.append(f"Flags: {pkt.flags} | Seq: {pkt.seq} | Ack: {pkt.ack}")
        lines.append("")
        lines.append("[bold]Raw Packet:[/bold]")
        lines.append("")

        # Get hex dump and apply scroll
        hex_lines = pkt.hex_dump().split("\n")
        total_lines = len(hex_lines)

        # Clamp scroll offset
        max_offset = max(0, total_lines - self.max_hex_lines)
        self.scroll_offset = min(self.scroll_offset, max_offset)

        visible_lines = hex_lines[self.scroll_offset:self.scroll_offset + self.max_hex_lines]

        for line in visible_lines:
            # Color the hex dump
            if line:
                parts = line.split("  ", 2)
                if len(parts) >= 3:
                    offset_part = f"[dim]{parts[0]}[/dim]"
                    hex_part = f"[cyan]{parts[1]}[/cyan]"
                    ascii_part = f"[green]{parts[2]}[/green]"
                    lines.append(f"{offset_part}  {hex_part}  {ascii_part}")
                else:
                    lines.append(line)

        if total_lines > self.max_hex_lines:
            lines.append("")
            lines.append(f"[dim]Showing lines {self.scroll_offset + 1}-{min(self.scroll_offset + self.max_hex_lines, total_lines)} of {total_lines} (↑↓ to scroll)[/dim]")

        title = f"[bold]Hex Dump[/bold] - Packet #{self.selected_packet_index}"
        return Panel("\n".join(lines), title=title, border_style="cyan")

    def _render_payload(self, inspection: FlowInspection) -> Panel:
        """Render payload analysis."""
        if not inspection.packets:
            return Panel("[dim]No packets captured[/dim]", title="[bold]Payload[/bold]", border_style="blue")

        pkt = inspection.packets[self.selected_packet_index]

        lines = []
        lines.append(f"[bold]Packet #{self.selected_packet_index} Payload[/bold]")
        lines.append(f"Payload size: {len(pkt.payload)} bytes")
        lines.append("")

        if not pkt.payload:
            lines.append("[dim]No application payload in this packet[/dim]")
        else:
            lines.append("[bold]Payload Hex:[/bold]")
            lines.append("")

            # Payload hex dump
            hex_lines = pkt.payload_hex_dump().split("\n")
            for line in hex_lines[:self.max_hex_lines]:
                if line:
                    parts = line.split("  ", 2)
                    if len(parts) >= 3:
                        offset_part = f"[dim]{parts[0]}[/dim]"
                        hex_part = f"[yellow]{parts[1]}[/yellow]"
                        ascii_part = f"[green]{parts[2]}[/green]"
                        lines.append(f"{offset_part}  {hex_part}  {ascii_part}")
                    else:
                        lines.append(line)

            if len(hex_lines) > self.max_hex_lines:
                lines.append(f"[dim]... ({len(hex_lines) - self.max_hex_lines} more lines)[/dim]")

            # ASCII preview
            lines.append("")
            lines.append("[bold]ASCII Preview:[/bold]")
            ascii_preview = pkt.payload_ascii[:500]
            if len(pkt.payload_ascii) > 500:
                ascii_preview += "..."
            lines.append(f"[dim]{ascii_preview}[/dim]")

        title = f"[bold]Payload Analysis[/bold] - Packet #{self.selected_packet_index}"
        return Panel("\n".join(lines), title=title, border_style="yellow")

    def _render_analysis(self, inspection: FlowInspection) -> Panel:
        """Render deductive analysis."""
        # Trigger analysis
        self.dpi.analyze_flow(self._active_flow_key)

        lines = []
        lines.append("[bold cyan]Deductive Analysis[/bold cyan]")
        lines.append("")

        if not inspection.analysis_notes:
            lines.append("[dim]No analysis available yet. Capture more packets.[/dim]")
        else:
            for note in inspection.analysis_notes:
                # Color certain keywords
                if "Warning" in note:
                    lines.append(f"[yellow]! {note}[/yellow]")
                elif "encrypted" in note.lower():
                    lines.append(f"[green]* {note}[/green]")
                elif "Detected" in note or "appears to be" in note:
                    lines.append(f"[cyan]* {note}[/cyan]")
                else:
                    lines.append(f"  {note}")

        lines.append("")
        lines.append("[bold]Fingerprint Reasoning:[/bold]")

        if inspection.src_fingerprint and inspection.src_fingerprint.reasoning:
            lines.append("")
            lines.append("[bold]Source:[/bold]")
            for reason in inspection.src_fingerprint.reasoning:
                lines.append(f"  - {reason}")

        if inspection.dst_fingerprint and inspection.dst_fingerprint.reasoning:
            lines.append("")
            lines.append("[bold]Destination:[/bold]")
            for reason in inspection.dst_fingerprint.reasoning:
                lines.append(f"  - {reason}")

        # Combined payload summary
        lines.append("")
        lines.append("[bold]Stream Summary:[/bold]")

        sent_payload = self.dpi.get_combined_payload(self._active_flow_key, "send")
        recv_payload = self.dpi.get_combined_payload(self._active_flow_key, "recv")

        lines.append(f"  Sent payload:     {format_bytes(len(sent_payload))}")
        lines.append(f"  Received payload: {format_bytes(len(recv_payload))}")

        return Panel("\n".join(lines), title="[bold]Analysis[/bold]", border_style="magenta")

    def _render_controls(self) -> Panel:
        """Render control hints."""
        controls = [
            "[bold]v[/bold]=View mode",
            "[bold]←→[/bold]=Prev/Next pkt",
            "[bold]↑↓[/bold]=Scroll",
            "[bold]c[/bold]=Clear",
        ]
        return Panel(" | ".join(controls), border_style="dim")

    def render(self) -> RenderableType:
        """Render the DPI panel."""
        if not self._active_flow_key:
            return self._render_no_selection()

        inspection = self.dpi.get_inspection(self._active_flow_key)
        if not inspection:
            # Create empty inspection for display
            return self._render_no_selection()

        # Render based on view mode
        if self.view_mode == DPIViewMode.OVERVIEW:
            main_panel = self._render_overview(inspection)
        elif self.view_mode == DPIViewMode.PACKETS:
            main_panel = self._render_packets_list(inspection)
        elif self.view_mode == DPIViewMode.HEX_DUMP:
            main_panel = self._render_hex_dump(inspection)
        elif self.view_mode == DPIViewMode.PAYLOAD:
            main_panel = self._render_payload(inspection)
        else:  # ANALYSIS
            main_panel = self._render_analysis(inspection)

        # Status bar
        status = f"View: {self.view_mode} | Packets: {len(inspection.packets)} | Target: {self._active_flow_key[:40]}..."

        return Group(
            main_panel,
            Panel(status, border_style="dim"),
        )
