"""ASCII graph utilities for terminal visualization."""

from typing import Dict, List, Optional, Tuple
from rich.text import Text


# Block characters for different fill levels
BLOCKS = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█']
HORIZONTAL_BLOCKS = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█']


def sparkline(
    data: List[float],
    width: int = 20,
    min_val: Optional[float] = None,
    max_val: Optional[float] = None,
    style: str = "green"
) -> Text:
    """Create a sparkline graph.

    Args:
        data: List of numeric values
        width: Maximum width of the sparkline
        min_val: Minimum value for scaling (auto if None)
        max_val: Maximum value for scaling (auto if None)
        style: Rich style for the sparkline

    Returns:
        Rich Text object containing the sparkline
    """
    if not data:
        return Text("─" * width, style="dim")

    # Take last 'width' values
    data = data[-width:]

    # Calculate range
    if min_val is None:
        min_val = min(data)
    if max_val is None:
        max_val = max(data)

    # Handle flat data
    value_range = max_val - min_val
    if value_range == 0:
        return Text(BLOCKS[4] * len(data), style=style)

    # Build sparkline
    chars = []
    for val in data:
        # Normalize to 0-8 range for block selection
        normalized = (val - min_val) / value_range
        block_idx = int(normalized * 8)
        block_idx = max(0, min(8, block_idx))
        chars.append(BLOCKS[block_idx])

    return Text(''.join(chars), style=style)


def bar_chart(
    data: Dict[str, float],
    width: int = 40,
    max_label_width: int = 15,
    show_values: bool = True,
    style: str = "cyan"
) -> str:
    """Create a horizontal bar chart.

    Args:
        data: Dictionary of label -> value
        width: Total width of the chart
        max_label_width: Maximum width for labels
        show_values: Whether to show numeric values
        style: Rich style for the bars

    Returns:
        Multi-line string containing the bar chart
    """
    if not data:
        return "[dim]No data[/dim]"

    lines = []
    max_val = max(data.values()) if data else 1
    bar_width = width - max_label_width - (10 if show_values else 0)

    for label, value in data.items():
        # Truncate label
        label_str = label[:max_label_width].ljust(max_label_width)

        # Calculate bar length
        bar_len = int((value / max_val) * bar_width) if max_val > 0 else 0
        bar = "█" * bar_len

        if show_values:
            value_str = _format_number(value)
            lines.append(f"[dim]{label_str}[/dim] [{style}]{bar:{bar_width}}[/{style}] {value_str}")
        else:
            lines.append(f"[dim]{label_str}[/dim] [{style}]{bar}[/{style}]")

    return '\n'.join(lines)


def vertical_bar_chart(
    data: Dict[str, float],
    height: int = 10,
    bar_width: int = 3,
    show_labels: bool = True,
    style: str = "green"
) -> str:
    """Create a vertical bar chart.

    Args:
        data: Dictionary of label -> value
        height: Height of the chart in lines
        bar_width: Width of each bar
        show_labels: Whether to show labels below bars
        style: Rich style for the bars

    Returns:
        Multi-line string containing the vertical bar chart
    """
    if not data:
        return "[dim]No data[/dim]"

    max_val = max(data.values()) if data else 1
    labels = list(data.keys())
    values = list(data.values())

    # Build chart from top to bottom
    lines = []
    for row in range(height, 0, -1):
        row_chars = []
        threshold = (row / height) * max_val

        for val in values:
            if val >= threshold:
                row_chars.append(f"[{style}]{'█' * bar_width}[/{style}]")
            else:
                row_chars.append(' ' * bar_width)

        lines.append(' '.join(row_chars))

    # Add baseline
    lines.append('─' * (len(values) * (bar_width + 1) - 1))

    # Add labels
    if show_labels:
        label_line = []
        for label in labels:
            truncated = label[:bar_width]
            centered = truncated.center(bar_width)
            label_line.append(centered)
        lines.append(' '.join(label_line))

    return '\n'.join(lines)


def histogram(
    data: List[float],
    bins: int = 10,
    width: int = 40,
    height: int = 8,
    style: str = "blue"
) -> str:
    """Create a histogram from data.

    Args:
        data: List of numeric values
        bins: Number of bins
        width: Width of the histogram
        height: Height of the histogram
        style: Rich style for the bars

    Returns:
        Multi-line string containing the histogram
    """
    if not data:
        return "[dim]No data[/dim]"

    # Calculate bin edges and counts
    min_val, max_val = min(data), max(data)
    if min_val == max_val:
        return f"[dim]All values are {min_val}[/dim]"

    bin_width = (max_val - min_val) / bins
    bin_counts = [0] * bins

    for val in data:
        bin_idx = int((val - min_val) / bin_width)
        bin_idx = min(bin_idx, bins - 1)
        bin_counts[bin_idx] += 1

    max_count = max(bin_counts)
    bar_width = width // bins

    # Build histogram
    lines = []
    for row in range(height, 0, -1):
        row_chars = []
        threshold = (row / height) * max_count

        for count in bin_counts:
            if count >= threshold:
                row_chars.append(f"[{style}]{'█' * bar_width}[/{style}]")
            else:
                row_chars.append(' ' * bar_width)

        lines.append(''.join(row_chars))

    # Add axis
    lines.append('─' * width)

    # Add range labels
    lines.append(f"[dim]{min_val:.1f}{' ' * (width - 12)}{max_val:.1f}[/dim]")

    return '\n'.join(lines)


def line_chart(
    data: List[float],
    width: int = 60,
    height: int = 10,
    show_axis: bool = True,
    style: str = "green"
) -> str:
    """Create a simple ASCII line chart.

    Args:
        data: List of numeric values
        width: Width of the chart
        height: Height of the chart
        show_axis: Whether to show axis
        style: Rich style for the line

    Returns:
        Multi-line string containing the line chart
    """
    if not data:
        return "[dim]No data[/dim]"

    # Resample data to fit width
    if len(data) > width:
        step = len(data) / width
        resampled = []
        for i in range(width):
            idx = int(i * step)
            resampled.append(data[idx])
        data = resampled
    elif len(data) < width:
        # Pad with last value
        data = data + [data[-1]] * (width - len(data))

    min_val, max_val = min(data), max(data)
    value_range = max_val - min_val if max_val != min_val else 1

    # Create grid
    grid = [[' ' for _ in range(width)] for _ in range(height)]

    # Plot points
    prev_y = None
    for x, val in enumerate(data):
        y = int((1 - (val - min_val) / value_range) * (height - 1))
        y = max(0, min(height - 1, y))

        # Draw line between points
        if prev_y is not None and prev_y != y:
            step = 1 if y > prev_y else -1
            for iy in range(prev_y + step, y + step, step):
                if 0 <= iy < height:
                    grid[iy][x] = '│'

        grid[y][x] = '●'
        prev_y = y

    # Convert grid to string
    lines = []
    for row in grid:
        lines.append(f"[{style}]{''.join(row)}[/{style}]")

    if show_axis:
        lines.append('└' + '─' * (width - 1))
        lines.append(f"[dim]{min_val:.1f}{' ' * (width - 12)}{max_val:.1f}[/dim]")

    return '\n'.join(lines)


def progress_bar(
    value: float,
    total: float,
    width: int = 30,
    filled_style: str = "green",
    empty_style: str = "dim"
) -> Text:
    """Create a progress bar.

    Args:
        value: Current value
        total: Total/maximum value
        width: Width of the progress bar
        filled_style: Style for filled portion
        empty_style: Style for empty portion

    Returns:
        Rich Text object containing the progress bar
    """
    if total <= 0:
        return Text("█" * width, style=empty_style)

    pct = min(1.0, value / total)
    filled = int(pct * width)
    empty = width - filled

    text = Text()
    text.append("█" * filled, style=filled_style)
    text.append("░" * empty, style=empty_style)
    text.append(f" {pct*100:.1f}%", style="dim")

    return text


def stacked_bar(
    values: List[Tuple[float, str]],
    total: float,
    width: int = 40,
    show_legend: bool = True
) -> str:
    """Create a stacked bar chart.

    Args:
        values: List of (value, style) tuples
        total: Total value for percentage calculation
        width: Width of the bar
        show_legend: Whether to show legend

    Returns:
        Multi-line string containing the stacked bar
    """
    if not values or total <= 0:
        return "[dim]No data[/dim]"

    lines = []
    bar_parts = []

    for value, style in values:
        segment_width = int((value / total) * width)
        if segment_width > 0:
            bar_parts.append(f"[{style}]{'█' * segment_width}[/{style}]")

    lines.append(''.join(bar_parts))

    if show_legend:
        legend_parts = []
        for value, style in values:
            pct = (value / total) * 100
            legend_parts.append(f"[{style}]█[/{style}] {pct:.1f}%")
        lines.append(' '.join(legend_parts))

    return '\n'.join(lines)


def _format_number(num: float) -> str:
    """Format number with appropriate suffix."""
    if num >= 1_000_000_000:
        return f"{num/1_000_000_000:.1f}G"
    if num >= 1_000_000:
        return f"{num/1_000_000:.1f}M"
    if num >= 1_000:
        return f"{num/1_000:.1f}K"
    return f"{num:.0f}"


def bandwidth_graph(
    data: List[float],
    width: int = 60,
    height: int = 8,
    label: str = "Bandwidth"
) -> str:
    """Create a bandwidth over time graph.

    Args:
        data: List of bandwidth values (bytes/sec)
        width: Width of the graph
        height: Height of the graph
        label: Label for the graph

    Returns:
        Multi-line string containing the bandwidth graph
    """
    if not data:
        return f"[bold]{label}[/bold]\n[dim]No data yet[/dim]"

    # Get current and max values
    current = data[-1] if data else 0
    max_val = max(data) if data else 0

    lines = []
    lines.append(f"[bold]{label}[/bold] [dim]Current: {_format_number(current)}/s | Max: {_format_number(max_val)}/s[/dim]")

    # Create sparkline
    spark = sparkline(data, width=width, style="green" if current < max_val * 0.8 else "yellow")
    lines.append(spark.plain)  # Convert to plain string for now

    return '\n'.join(lines)


def traffic_distribution(
    inbound: float,
    outbound: float,
    width: int = 40
) -> str:
    """Create a traffic distribution visualization.

    Args:
        inbound: Inbound bytes
        outbound: Outbound bytes
        width: Width of the visualization

    Returns:
        Multi-line string containing the distribution
    """
    total = inbound + outbound
    if total == 0:
        return "[dim]No traffic[/dim]"

    in_pct = inbound / total
    out_pct = outbound / total

    in_width = int(in_pct * width)
    out_width = width - in_width

    lines = []
    lines.append(f"[green]{'█' * in_width}[/green][cyan]{'█' * out_width}[/cyan]")
    lines.append(
        f"[green]↓ In: {_format_number(inbound)} ({in_pct*100:.1f}%)[/green]  "
        f"[cyan]↑ Out: {_format_number(outbound)} ({out_pct*100:.1f}%)[/cyan]"
    )

    return '\n'.join(lines)
