#!/usr/bin/env python3
"""PacketTracer - Network packet tracking with geo awareness."""

import argparse
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.table import Table

from capture.sniffer import PacketSniffer
from dashboard.app import Dashboard


def list_interfaces():
    """List available network interfaces."""
    console = Console()
    interfaces = PacketSniffer.list_interfaces()

    table = Table(title="Available Network Interfaces")
    table.add_column("Interface", style="cyan")

    for iface in interfaces:
        table.add_row(iface)

    console.print(table)


def check_permissions():
    """Check if running with sufficient permissions."""
    if os.geteuid() != 0:
        console = Console()
        console.print(
            "[bold red]Error:[/bold red] PacketTracer requires root/sudo privileges "
            "for packet capture.",
            style="red",
        )
        console.print("\nRun with: [bold]sudo python main.py[/bold]")
        return False
    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="PacketTracer - Network packet tracking with geo awareness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py                    # Start with auto-detected interface
  sudo python main.py -i eth0            # Use specific interface
  sudo python main.py -f "tcp port 80"   # Filter HTTP traffic only
  sudo python main.py --list             # List available interfaces
  sudo python main.py -t 8.8.8.8         # Traceroute to IP

Views:
  1 - Traffic    Live flow table with navigation and selection
  2 - Paths      Traceroute and hop analysis
  3 - Stats      Traffic statistics by country, ISP, protocol
  4 - Analysis   Packet analysis, traffic classification, encryption status
  5 - Ports      Port transit tracking, service breakdown

Controls (Traffic view):
  Arrow keys    Navigate flows
  Space         Select/deselect flow
  Enter         Traceroute to selected destination
  /             Filter by IP substring
  :             Filter by port
  f             Cycle protocol filter (All/TCP/UDP/ICMP)
  s             Cycle sort (bytes/packets/time)
  l             Toggle local traffic visibility
  a             Select all flows
  c             Clear filters and selection

Global:
  p - Pause/Resume      t - Traceroute       q - Quit
        """,
    )

    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (default: auto-detect)",
    )
    parser.add_argument(
        "-f", "--filter",
        default="ip",
        help="BPF filter expression (default: 'ip')",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available network interfaces and exit",
    )
    parser.add_argument(
        "-t", "--traceroute",
        metavar="TARGET",
        help="Start with traceroute to target IP/hostname",
    )
    parser.add_argument(
        "--no-geo",
        action="store_true",
        help="Disable geo/ISP lookups",
    )
    parser.add_argument(
        "--simple",
        action="store_true",
        help="Run without keyboard input handling (use Ctrl+C to exit)",
    )

    args = parser.parse_args()

    # List interfaces and exit
    if args.list:
        list_interfaces()
        return 0

    # Check permissions
    if not check_permissions():
        return 1

    console = Console()

    try:
        # Create and configure dashboard
        dashboard = Dashboard(
            interface=args.interface,
            bpf_filter=args.filter,
        )

        # Start traceroute if requested
        if args.traceroute:
            console.print(f"[cyan]Starting traceroute to {args.traceroute}...[/cyan]")
            dashboard.traceroute(args.traceroute)

        console.print("[green]Starting PacketTracer...[/green]")
        console.print("[dim]Press 'q' to quit, '?' for help[/dim]\n")

        # Run dashboard
        if args.simple:
            dashboard.run()
        else:
            dashboard.run_with_input()

    except PermissionError:
        console.print(
            "[bold red]Error:[/bold red] Permission denied. "
            "Make sure you're running with sudo.",
            style="red",
        )
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        return 1

    console.print("[green]PacketTracer stopped.[/green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
