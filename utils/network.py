"""Network utility functions."""

import ipaddress
import socket
from typing import Optional, Set

from config import GEO_API_HOST

# Cache of IPs to filter (ip-api.com servers)
_filtered_ips: Set[str] = set()
_filtered_ips_resolved = False


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private (RFC 1918) or special."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return True


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_packets(count: int) -> str:
    """Format packet count with K/M suffixes."""
    if count < 1000:
        return str(count)
    elif count < 1000000:
        return f"{count / 1000:.1f}K"
    else:
        return f"{count / 1000000:.1f}M"


def get_local_ip() -> Optional[str]:
    """Get the local IP address used for default routing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None


def get_default_interface() -> Optional[str]:
    """Get the default network interface name."""
    try:
        local_ip = get_local_ip()
        if not local_ip:
            return None

        # Try to find interface with this IP using scapy
        try:
            from scapy.all import get_if_list, get_if_addr

            for iface in get_if_list():
                if get_if_addr(iface) == local_ip:
                    return iface
        except ImportError:
            pass

        return None
    except Exception:
        return None


def resolve_hostname(ip: str) -> Optional[str]:
    """Reverse DNS lookup for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def get_service_name(port: int, protocol: str = "tcp") -> Optional[str]:
    """Get service name for a port number."""
    try:
        return socket.getservbyport(port, protocol)
    except (OSError, socket.error):
        return None


def _resolve_filtered_ips() -> None:
    """Resolve ip-api.com to IP addresses for filtering."""
    global _filtered_ips_resolved
    if _filtered_ips_resolved:
        return

    try:
        # Resolve ip-api.com to all its IP addresses
        _, _, ips = socket.gethostbyname_ex(GEO_API_HOST)
        _filtered_ips.update(ips)
    except (socket.herror, socket.gaierror):
        pass

    _filtered_ips_resolved = True


def is_api_traffic(ip: str) -> bool:
    """Check if an IP belongs to our API services (should be filtered from display)."""
    _resolve_filtered_ips()
    return ip in _filtered_ips


def add_filtered_ip(ip: str) -> None:
    """Add an IP to the filter list."""
    _filtered_ips.add(ip)
