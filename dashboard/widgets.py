"""Reusable Rich UI components."""

from typing import List, Optional, Dict, Any
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn
from rich.console import Group
from rich.style import Style

from utils.network import format_bytes, format_packets


def create_flow_table(
    flows: List[Any],
    title: str = "Active Flows",
    max_rows: int = 20,
) -> Table:
    """Create a table displaying network flows."""
    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        expand=True,
    )

    table.add_column("Source", style="green", no_wrap=True)
    table.add_column("Destination", style="yellow", no_wrap=True)
    table.add_column("Proto", style="magenta", justify="center", width=6)
    table.add_column("Sent", justify="right", width=10)
    table.add_column("Recv", justify="right", width=10)
    table.add_column("Pkts", justify="right", width=8)
    table.add_column("Hops", justify="center", width=5)
    table.add_column("Location", style="cyan", no_wrap=True)

    for flow in flows[:max_rows]:
        src = f"{flow.src_ip}:{flow.src_port}" if flow.src_port else flow.src_ip
        dst = f"{flow.dst_ip}:{flow.dst_port}" if flow.dst_port else flow.dst_ip

        # Get location if available
        location = ""
        if flow.dst_geo:
            geo = flow.dst_geo
            if isinstance(geo, dict):
                city = geo.get("city", "")
                country_code = geo.get("country_code", "")
                if city and country_code:
                    location = f"{city}, {country_code}"
            elif hasattr(geo, "city") and geo.city:
                location = f"{geo.city}, {geo.country_code}"

        hops = str(flow.estimated_hops) if flow.estimated_hops else "-"

        table.add_row(
            src,
            dst,
            flow.protocol_name,
            format_bytes(flow.bytes_sent),
            format_bytes(flow.bytes_recv),
            format_packets(flow.total_packets),
            hops,
            location,
        )

    return table


def create_hop_table(hops: List[Any], title: str = "Network Hops") -> Table:
    """Create a table displaying hop/path information."""
    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        expand=True,
    )

    table.add_column("#", justify="center", width=4)
    table.add_column("IP Address", style="green", no_wrap=True)
    table.add_column("Hostname", style="yellow")
    table.add_column("RTT (ms)", justify="right", width=12)
    table.add_column("Location", style="cyan")
    table.add_column("ISP/Org", style="magenta")

    for i, hop in enumerate(hops, 1):
        if hop.is_timeout:
            table.add_row(
                str(i),
                "*",
                "-",
                "-",
                "-",
                "-",
                style="dim",
            )
        else:
            rtt = f"{hop.avg_rtt:.1f}" if hop.avg_rtt else "-"
            hostname = hop.hostname or "-"
            location = ""
            isp = ""

            if hasattr(hop, "geo") and hop.geo:
                geo = hop.geo
                if isinstance(geo, dict):
                    city = geo.get("city", "")
                    country_code = geo.get("country_code", "")
                    if city and country_code:
                        location = f"{city}, {country_code}"
                    isp = geo.get("isp") or geo.get("org") or ""
                elif hasattr(geo, "city") and geo.city:
                    location = f"{geo.city}, {geo.country_code}"
                    isp = geo.isp or geo.org or ""

            style = "bold green" if hop.is_destination else None

            table.add_row(
                str(i),
                hop.ip or "*",
                hostname[:30] if hostname else "-",
                rtt,
                location,
                isp[:25] if isp else "-",
                style=style,
            )

    return table


def create_stats_panel(stats: Dict[str, Any], title: str = "Statistics") -> Panel:
    """Create a panel displaying statistics."""
    lines = []

    for key, value in stats.items():
        label = key.replace("_", " ").title()
        if isinstance(value, float):
            value_str = f"{value:.2f}"
        elif isinstance(value, int) and value > 1000000:
            value_str = format_bytes(value)
        else:
            value_str = str(value)

        lines.append(f"[cyan]{label}:[/cyan] [white]{value_str}[/white]")

    content = "\n".join(lines)
    return Panel(content, title=title, border_style="blue")


def create_progress_bar(
    current: int,
    total: int,
    label: str = "",
    color: str = "green",
) -> Text:
    """Create a simple progress bar as text."""
    if total == 0:
        percentage = 0
    else:
        percentage = min(100, int((current / total) * 100))

    bar_width = 20
    filled = int(bar_width * percentage / 100)
    empty = bar_width - filled

    bar = f"[{color}]{'█' * filled}{'░' * empty}[/{color}]"
    return Text.from_markup(f"{label} {bar} {percentage}%")


def create_geo_summary(geo_data: Dict[str, int], title: str = "Traffic by Country") -> Panel:
    """Create a panel showing traffic by country."""
    if not geo_data:
        return Panel("No geo data available", title=title, border_style="blue")

    # Sort by count
    sorted_data = sorted(geo_data.items(), key=lambda x: x[1], reverse=True)[:10]

    lines = []
    max_count = sorted_data[0][1] if sorted_data else 1

    for country, count in sorted_data:
        bar_len = int(20 * count / max_count)
        bar = "█" * bar_len
        lines.append(f"[cyan]{country:15}[/cyan] [green]{bar}[/green] {count}")

    content = "\n".join(lines)
    return Panel(content, title=title, border_style="blue")


def create_isp_summary(isp_data: Dict[str, int], title: str = "Traffic by ISP") -> Panel:
    """Create a panel showing traffic by ISP."""
    if not isp_data:
        return Panel("No ISP data available", title=title, border_style="blue")

    sorted_data = sorted(isp_data.items(), key=lambda x: x[1], reverse=True)[:10]

    lines = []
    max_count = sorted_data[0][1] if sorted_data else 1

    for isp, count in sorted_data:
        isp_display = isp[:25] if len(isp) > 25 else isp
        bar_len = int(15 * count / max_count)
        bar = "█" * bar_len
        lines.append(f"[yellow]{isp_display:25}[/yellow] [green]{bar}[/green] {count}")

    content = "\n".join(lines)
    return Panel(content, title=title, border_style="blue")
