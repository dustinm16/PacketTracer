"""DNS query tracking panel."""

import time
from typing import List, Optional
from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.text import Text
from rich.columns import Columns

from tracking.dns_tracker import DNSTracker


class DNSPanel:
    """Panel displaying DNS query statistics and analysis."""

    def __init__(self, dns_tracker: DNSTracker):
        self.dns_tracker = dns_tracker
        self.view_mode = "queries"  # queries, domains, nxdomain, servers
        self.show_count = 25
        self.query_filter: Optional[str] = None
        self.type_filter: Optional[str] = None
        self.only_responses = False
        self.only_nxdomain = False

    def cycle_view(self) -> str:
        """Cycle through view modes."""
        modes = ["queries", "domains", "nxdomain", "servers"]
        idx = modes.index(self.view_mode)
        self.view_mode = modes[(idx + 1) % len(modes)]
        return self.view_mode

    def toggle_responses_only(self) -> bool:
        """Toggle showing only responses."""
        self.only_responses = not self.only_responses
        return self.only_responses

    def toggle_nxdomain_only(self) -> bool:
        """Toggle showing only NXDOMAIN responses."""
        self.only_nxdomain = not self.only_nxdomain
        return self.only_nxdomain

    def set_query_filter(self, pattern: Optional[str]) -> None:
        """Set domain name filter pattern."""
        self.query_filter = pattern

    def set_type_filter(self, qtype: Optional[str]) -> None:
        """Set query type filter (A, AAAA, MX, etc.)."""
        self.type_filter = qtype

    def _format_timestamp(self, ts: float) -> str:
        """Format timestamp as relative time or absolute."""
        age = time.time() - ts
        if age < 60:
            return f"{age:.1f}s ago"
        elif age < 3600:
            return f"{age/60:.1f}m ago"
        else:
            return time.strftime("%H:%M:%S", time.localtime(ts))

    def _render_queries_table(self) -> Table:
        """Render recent DNS queries table."""
        queries = self.dns_tracker.get_queries(
            limit=self.show_count,
            query_name=self.query_filter,
            query_type=self.type_filter,
            only_responses=self.only_responses,
            only_nxdomain=self.only_nxdomain,
        )

        # Build title with filters
        title_parts = ["[bold]Recent DNS Queries[/bold]"]
        if self.only_responses:
            title_parts.append("[yellow](Responses Only)[/yellow]")
        if self.only_nxdomain:
            title_parts.append("[red](NXDOMAIN Only)[/red]")
        if self.query_filter:
            title_parts.append(f"[cyan](Filter: {self.query_filter})[/cyan]")
        if self.type_filter:
            title_parts.append(f"[magenta](Type: {self.type_filter})[/magenta]")

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title=" ".join(title_parts),
        )

        table.add_column("Time", style="dim", width=10)
        table.add_column("Type", style="magenta", width=6)
        table.add_column("Q/R", style="yellow", width=3)
        table.add_column("Domain", style="cyan", no_wrap=False)
        table.add_column("Answers/Code", style="green")
        table.add_column("Server", style="dim", width=15)

        for record in queries:
            # Format Q/R indicator
            if record.is_response:
                qr = "R"
                qr_style = "green" if record.response_code == 0 else "red"
            else:
                qr = "Q"
                qr_style = "cyan"

            # Format answers or response code
            if record.is_response:
                if record.response_code == 0:
                    if record.answers:
                        # Show first answer IP or data
                        first_answer = record.answers[0] if record.answers else {}
                        answer_str = first_answer.get("rdata", "")[:20]
                        if record.answer_count > 1:
                            answer_str += f" +{record.answer_count - 1}"
                        answer_style = "green"
                    else:
                        answer_str = "No answers"
                        answer_style = "yellow"
                else:
                    answer_str = record.response_code_name or f"Error {record.response_code}"
                    answer_style = "red" if record.is_nxdomain else "yellow"
            else:
                answer_str = "-"
                answer_style = "dim"

            # Server IP (dst for queries, src for responses)
            server_ip = record.dst_ip if not record.is_response else record.src_ip

            table.add_row(
                self._format_timestamp(record.timestamp),
                record.query_type_name,
                Text(qr, style=qr_style),
                record.query_name,
                Text(answer_str, style=answer_style),
                server_ip,
            )

        return table

    def _render_top_domains(self) -> Table:
        """Render top queried domains table."""
        domains = self.dns_tracker.get_top_queried_domains(limit=self.show_count)

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title="[bold]Top Queried Domains[/bold]",
        )

        table.add_column("Domain", style="cyan", no_wrap=False)
        table.add_column("Queries", justify="right", width=8)
        table.add_column("Responses", justify="right", width=10)
        table.add_column("NXDOMAIN", justify="right", width=9)
        table.add_column("Errors", justify="right", width=7)
        table.add_column("Latency", justify="right", width=8)

        for domain in domains:
            # Color coding for issues
            nxdomain_style = "red" if domain.get("nxdomain_count", 0) > 0 else "dim"
            error_style = "yellow" if domain.get("error_count", 0) > 0 else "dim"

            latency = domain.get("avg_latency_ms")
            latency_str = f"{latency:.1f}ms" if latency else "-"

            table.add_row(
                domain.get("query_name", ""),
                str(domain.get("query_count", 0)),
                str(domain.get("response_count", 0)),
                Text(str(domain.get("nxdomain_count", 0)), style=nxdomain_style),
                Text(str(domain.get("error_count", 0)), style=error_style),
                latency_str,
            )

        return table

    def _render_nxdomain_table(self) -> Table:
        """Render NXDOMAIN domains table (potential DGA detection)."""
        domains = self.dns_tracker.get_nxdomain_domains(limit=self.show_count)

        table = Table(
            show_header=True,
            header_style="bold red",
            border_style="red",
            expand=True,
            title="[bold red]NXDOMAIN Domains (Potential DGA/Typos)[/bold red]",
        )

        table.add_column("Domain", style="red", no_wrap=False)
        table.add_column("Count", justify="right", width=8)
        table.add_column("First Seen", width=12)
        table.add_column("Last Seen", width=12)
        table.add_column("Suspicious", width=10)

        for domain in domains:
            domain_name = domain.get("query_name", "")
            count = domain.get("nxdomain_count", 0)

            # DGA detection heuristics
            suspicious = []
            if len(domain_name) > 30:
                suspicious.append("long")
            if sum(c.isdigit() for c in domain_name) > 5:
                suspicious.append("nums")
            if not any(c.isalpha() for c in domain_name.split(".")[0][-4:]):
                suspicious.append("random")

            suspicious_str = ", ".join(suspicious) if suspicious else "-"
            suspicious_style = "bold red" if suspicious else "dim"

            table.add_row(
                domain_name,
                str(count),
                self._format_timestamp(domain.get("first_seen", 0)),
                self._format_timestamp(domain.get("last_seen", 0)),
                Text(suspicious_str, style=suspicious_style),
            )

        return table

    def _render_dns_servers(self) -> Table:
        """Render DNS servers used."""
        servers = self.dns_tracker.get_dns_servers()

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            title="[bold]DNS Servers Used[/bold]",
        )

        table.add_column("Server IP", style="cyan", width=20)
        table.add_column("Query Count", justify="right", width=12)
        table.add_column("Bar", width=30)

        max_count = servers[0].get("query_count", 1) if servers else 1
        for server in servers:
            count = server.get("query_count", 0)
            bar_len = int(25 * count / max(1, max_count))
            bar = "█" * bar_len

            table.add_row(
                server.get("server_ip", ""),
                str(count),
                Text(bar, style="green"),
            )

        return table

    def _render_query_types(self) -> Panel:
        """Render query type breakdown."""
        breakdown = self.dns_tracker.get_query_type_breakdown()

        lines = []
        total = sum(item.get("count", 0) for item in breakdown)

        for item in breakdown[:10]:
            qtype = item.get("query_type_name", "?")
            count = item.get("count", 0)
            pct = (count / max(1, total)) * 100
            bar_len = int(pct / 5)
            bar = "█" * bar_len

            lines.append(
                f"[magenta]{qtype:8}[/magenta] [green]{bar:20}[/green] "
                f"{count:>6} ({pct:5.1f}%)"
            )

        return Panel(
            "\n".join(lines) if lines else "[dim]No query data yet[/dim]",
            title="[bold]Query Types[/bold]",
            border_style="blue",
        )

    def _render_stats_summary(self) -> Panel:
        """Render DNS statistics summary."""
        stats = self.dns_tracker.get_summary_stats()

        lines = [
            f"[cyan]Total Queries:[/cyan]    {stats['total_queries']:>8}",
            f"[green]Total Responses:[/green]  {stats['total_responses']:>8}",
            f"[red]NXDOMAIN:[/red]          {stats['nxdomain_count']:>8}",
            f"[yellow]Errors:[/yellow]            {stats['error_count']:>8}",
            f"[dim]Pending:[/dim]            {stats['pending_queries']:>8}",
        ]

        # Calculate response rate
        if stats['total_queries'] > 0:
            response_rate = (stats['total_responses'] / stats['total_queries']) * 100
            lines.append(f"[blue]Response Rate:[/blue]    {response_rate:>7.1f}%")

        # NXDOMAIN rate
        if stats['total_responses'] > 0:
            nxdomain_rate = (stats['nxdomain_count'] / stats['total_responses']) * 100
            nxdomain_style = "red" if nxdomain_rate > 10 else "green"
            lines.append(f"[{nxdomain_style}]NXDOMAIN Rate:[/{nxdomain_style}]    {nxdomain_rate:>7.1f}%")

        return Panel(
            "\n".join(lines),
            title="[bold]DNS Statistics[/bold]",
            border_style="blue",
        )

    def _render_summary_bar(self) -> Text:
        """Render summary status bar."""
        stats = self.dns_tracker.get_summary_stats()

        nxdomain_warning = ""
        if stats['nxdomain_count'] > 10:
            nxdomain_warning = f" [bold red]| {stats['nxdomain_count']} NXDOMAIN[/bold red]"

        return Text.from_markup(
            f"[dim]View: {self.view_mode} (press 'v' to change) | "
            f"Queries: {stats['total_queries']} | "
            f"Responses: {stats['total_responses']}"
            f"{nxdomain_warning}[/dim] | "
            f"[dim]'r' = responses only, 'n' = nxdomain only[/dim]"
        )

    def render(self) -> RenderableType:
        """Render the DNS panel based on current view mode."""
        if self.view_mode == "queries":
            main_table = self._render_queries_table()
        elif self.view_mode == "domains":
            main_table = self._render_top_domains()
        elif self.view_mode == "nxdomain":
            main_table = self._render_nxdomain_table()
        elif self.view_mode == "servers":
            main_table = self._render_dns_servers()
        else:
            main_table = self._render_queries_table()

        # Side panels
        side_panels = Columns([
            self._render_query_types(),
            self._render_stats_summary(),
        ], expand=True)

        # Summary bar
        summary = self._render_summary_bar()

        return Group(main_table, side_panels, summary)
