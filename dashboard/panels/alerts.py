"""Alerts panel for security monitoring."""

from typing import List, Optional
from datetime import datetime

from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.columns import Columns
from rich.text import Text

from security.alerts import AlertEngine, Alert, AlertSeverity


class AlertsPanel:
    """Panel displaying security alerts."""

    def __init__(self, alert_engine: AlertEngine):
        self.alert_engine = alert_engine
        self.show_acknowledged = False
        self.filter_severity: Optional[AlertSeverity] = None
        self.selected_index = 0

    def toggle_acknowledged(self) -> bool:
        """Toggle showing acknowledged alerts."""
        self.show_acknowledged = not self.show_acknowledged
        return self.show_acknowledged

    def cycle_severity_filter(self) -> Optional[str]:
        """Cycle through severity filters."""
        severities = [None, AlertSeverity.CRITICAL, AlertSeverity.HIGH,
                      AlertSeverity.MEDIUM, AlertSeverity.LOW, AlertSeverity.INFO]
        current_idx = severities.index(self.filter_severity) if self.filter_severity in severities else 0
        next_idx = (current_idx + 1) % len(severities)
        self.filter_severity = severities[next_idx]
        return self.filter_severity.name if self.filter_severity else None

    def acknowledge_selected(self) -> bool:
        """Acknowledge the currently selected alert."""
        alerts = self._get_filtered_alerts()
        if 0 <= self.selected_index < len(alerts):
            self.alert_engine.acknowledge_alert(alerts[self.selected_index].id)
            return True
        return False

    def acknowledge_all(self) -> int:
        """Acknowledge all visible alerts."""
        alerts = self._get_filtered_alerts()
        count = 0
        for alert in alerts:
            if not alert.acknowledged:
                self.alert_engine.acknowledge_alert(alert.id)
                count += 1
        return count

    def move_up(self) -> None:
        """Move selection up."""
        if self.selected_index > 0:
            self.selected_index -= 1

    def move_down(self) -> None:
        """Move selection down."""
        alerts = self._get_filtered_alerts()
        if self.selected_index < len(alerts) - 1:
            self.selected_index += 1

    def _get_filtered_alerts(self) -> List[Alert]:
        """Get alerts based on current filters."""
        # Use unacknowledged_only parameter correctly
        alerts = self.alert_engine.get_alerts(
            severity=self.filter_severity,
            unacknowledged_only=not self.show_acknowledged
        )
        return alerts

    def _severity_style(self, severity: AlertSeverity) -> str:
        """Get Rich style for severity level."""
        styles = {
            AlertSeverity.CRITICAL: "bold white on red",
            AlertSeverity.HIGH: "bold red",
            AlertSeverity.MEDIUM: "yellow",
            AlertSeverity.LOW: "cyan",
            AlertSeverity.INFO: "dim",
        }
        return styles.get(severity, "white")

    def _severity_icon(self, severity: AlertSeverity) -> str:
        """Get icon for severity level."""
        icons = {
            AlertSeverity.CRITICAL: "!!!",
            AlertSeverity.HIGH: "!! ",
            AlertSeverity.MEDIUM: "!  ",
            AlertSeverity.LOW: ".  ",
            AlertSeverity.INFO: "   ",
        }
        return icons.get(severity, "   ")

    def _format_timestamp(self, ts: float) -> str:
        """Format a timestamp (float) to time string."""
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")

    def _render_alerts_table(self) -> Panel:
        """Render the alerts table."""
        alerts = self._get_filtered_alerts()

        if not alerts:
            msg = "No alerts"
            if self.filter_severity:
                msg += f" (filter: {self.filter_severity.name})"
            if not self.show_acknowledged:
                msg += " - press 'a' to show acknowledged"
            return Panel(f"[dim]{msg}[/dim]", title="[bold]Alerts[/bold]", border_style="green")

        table = Table(show_header=True, header_style="bold", box=None, expand=True)
        table.add_column("", width=3)  # Severity icon
        table.add_column("Time", width=8)
        table.add_column("Type", width=15)
        table.add_column("Description", ratio=2)
        table.add_column("Source", width=15)
        table.add_column("Target", width=15)

        # Ensure selected index is valid
        if self.selected_index >= len(alerts):
            self.selected_index = max(0, len(alerts) - 1)

        for i, alert in enumerate(alerts[:50]):  # Limit display
            style = self._severity_style(alert.severity)
            icon = self._severity_icon(alert.severity)

            # Highlight selected row
            row_style = "reverse" if i == self.selected_index else ""

            # Dim acknowledged alerts
            if alert.acknowledged:
                style = "dim"
                row_style = "dim"

            time_str = self._format_timestamp(alert.timestamp)
            desc = alert.description[:50] + "..." if len(alert.description) > 50 else alert.description
            src = alert.source_ip or ""
            dst = alert.dest_ip or ""  # Use dest_ip, not destination_ip

            table.add_row(
                Text(icon, style=style),
                time_str,
                Text(alert.alert_type.value, style=style),
                desc,
                src,
                dst,
                style=row_style,
            )

        title = f"[bold]Alerts[/bold] ({len(alerts)} total)"
        if self.filter_severity:
            title += f" [yellow][{self.filter_severity.name}][/yellow]"

        return Panel(table, title=title, border_style="red" if any(a.severity == AlertSeverity.CRITICAL for a in alerts) else "yellow")

    def _render_stats(self) -> Panel:
        """Render alert statistics."""
        stats = self.alert_engine.get_stats()

        lines = []
        lines.append(f"[cyan]Total Alerts:[/cyan]      {stats['total_alerts']:>6}")
        lines.append(f"[cyan]Unacknowledged:[/cyan]    {stats['unacknowledged']:>6}")
        lines.append("")
        lines.append("[bold]By Severity:[/bold]")

        # Map severity names to enum values for styling
        severity_map = {
            "CRITICAL": AlertSeverity.CRITICAL,
            "HIGH": AlertSeverity.HIGH,
            "MEDIUM": AlertSeverity.MEDIUM,
            "LOW": AlertSeverity.LOW,
            "INFO": AlertSeverity.INFO,
        }

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in severity_order:
            count = stats['by_severity'].get(sev, 0)
            if count > 0:
                style = self._severity_style(severity_map.get(sev, AlertSeverity.INFO))
                bar_len = min(20, count)
                bar = "█" * bar_len
                lines.append(f"  [{style}]{sev:10}[/{style}] {bar} {count}")

        # Additional stats
        lines.append("")
        lines.append(f"[cyan]Generated:[/cyan]         {stats.get('alerts_generated', 0):>6}")
        lines.append(f"[cyan]Suppressed:[/cyan]        {stats.get('alerts_suppressed', 0):>6}")
        lines.append(f"[cyan]Known Hosts:[/cyan]       {stats.get('known_hosts', 0):>6}")

        return Panel("\n".join(lines), title="[bold]Statistics[/bold]", border_style="blue")

    def _render_rules(self) -> Panel:
        """Render active alert rules."""
        rules = self.alert_engine.get_rules()  # Use get_rules() method

        lines = []
        lines.append(f"[cyan]Active Rules:[/cyan] {len([r for r in rules if r.enabled])}/{len(rules)}")
        lines.append("")

        for rule in rules[:10]:
            status = "[green]●[/green]" if rule.enabled else "[red]○[/red]"
            sev_style = self._severity_style(rule.severity)
            lines.append(f"{status} [{sev_style}]{rule.name:25}[/{sev_style}] cooldown={rule.cooldown}s")

        return Panel("\n".join(lines), title="[bold]Alert Rules[/bold]", border_style="blue")

    def _render_recent_critical(self) -> Panel:
        """Render recent critical/high alerts summary."""
        critical_alerts = self.alert_engine.get_alerts(severity=AlertSeverity.CRITICAL)
        high_alerts = self.alert_engine.get_alerts(severity=AlertSeverity.HIGH)

        recent = sorted(
            critical_alerts + high_alerts,
            key=lambda a: a.timestamp,
            reverse=True
        )[:5]

        if not recent:
            return Panel("[green]No critical or high severity alerts[/green]",
                        title="[bold]Critical/High Alerts[/bold]", border_style="green")

        lines = []
        for alert in recent:
            style = self._severity_style(alert.severity)
            icon = self._severity_icon(alert.severity)
            time_str = self._format_timestamp(alert.timestamp)
            title = alert.title[:40] + "..." if len(alert.title) > 40 else alert.title
            lines.append(f"[{style}]{icon}[/{style}] {time_str} {title}")

        return Panel("\n".join(lines), title="[bold]Critical/High Alerts[/bold]",
                    border_style="red" if critical_alerts else "yellow")

    def render(self) -> RenderableType:
        """Render the alerts panel."""
        # Main alerts table on top
        alerts_table = self._render_alerts_table()

        # Bottom row: stats, rules, critical summary
        bottom_row = Columns([
            self._render_stats(),
            self._render_rules(),
            self._render_recent_critical(),
        ], expand=True)

        return Group(alerts_table, bottom_row)
