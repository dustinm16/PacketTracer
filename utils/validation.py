"""Input validation utilities for PacketTracer."""

import ipaddress
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def validate_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """Validate an IP address (IPv4 or IPv6).

    Args:
        ip: IP address string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip:
        return False, "IP address cannot be empty"

    try:
        ipaddress.ip_address(ip)
        return True, None
    except ValueError as e:
        return False, f"Invalid IP address: {e}"


def validate_port(port: int) -> Tuple[bool, Optional[str]]:
    """Validate a port number.

    Args:
        port: Port number to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(port, int):
        return False, f"Port must be an integer, got {type(port).__name__}"

    if port < 0 or port > 65535:
        return False, f"Port must be between 0 and 65535, got {port}"

    return True, None


def validate_port_range(start_port: int, end_port: int) -> Tuple[bool, Optional[str]]:
    """Validate a port range.

    Args:
        start_port: Start of port range
        end_port: End of port range

    Returns:
        Tuple of (is_valid, error_message)
    """
    valid, err = validate_port(start_port)
    if not valid:
        return False, f"Invalid start port: {err}"

    valid, err = validate_port(end_port)
    if not valid:
        return False, f"Invalid end port: {err}"

    if start_port > end_port:
        return False, f"Start port ({start_port}) must be <= end port ({end_port})"

    return True, None


def validate_bpf_filter(filter_str: str) -> Tuple[bool, Optional[str]]:
    """Validate a BPF filter string by attempting to compile it.

    Args:
        filter_str: BPF filter expression to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not filter_str:
        return True, None  # Empty filter is valid (captures all)

    try:
        # Try to compile the filter using scapy
        from scapy.arch import compile_filter
        compile_filter(filter_str)
        return True, None
    except ImportError:
        # scapy not available, skip validation
        logger.warning("Cannot validate BPF filter: scapy not available")
        return True, None
    except Exception as e:
        return False, f"Invalid BPF filter: {e}"


def validate_timeout(value: float, name: str = "timeout") -> Tuple[bool, Optional[str]]:
    """Validate a timeout value.

    Args:
        value: Timeout value to validate
        name: Name of the parameter for error messages

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(value, (int, float)):
        return False, f"{name} must be a number, got {type(value).__name__}"

    if value <= 0:
        return False, f"{name} must be positive, got {value}"

    if value > 3600:
        return False, f"{name} too large (max 3600 seconds), got {value}"

    return True, None


def validate_positive_int(value: int, name: str = "value", max_value: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """Validate a positive integer.

    Args:
        value: Integer to validate
        name: Name of the parameter for error messages
        max_value: Optional maximum value

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(value, int):
        return False, f"{name} must be an integer, got {type(value).__name__}"

    if value <= 0:
        return False, f"{name} must be positive, got {value}"

    if max_value is not None and value > max_value:
        return False, f"{name} too large (max {max_value}), got {value}"

    return True, None


def validate_interface(interface: str) -> Tuple[bool, Optional[str]]:
    """Validate a network interface name.

    Args:
        interface: Network interface name to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not interface:
        return False, "Interface name cannot be empty"

    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        if interface not in interfaces:
            return False, f"Interface '{interface}' not found. Available: {', '.join(interfaces)}"
        return True, None
    except ImportError:
        # scapy not available, accept any interface
        return True, None
    except Exception as e:
        logger.warning(f"Cannot validate interface: {e}")
        return True, None


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Validate a URL.

    Args:
        url: URL string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return False, "URL cannot be empty"

    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        if not result.scheme:
            return False, "URL missing scheme (http:// or https://)"
        if result.scheme not in ('http', 'https'):
            return False, f"Invalid URL scheme: {result.scheme}"
        if not result.netloc:
            return False, "URL missing host"
        return True, None
    except Exception as e:
        return False, f"Invalid URL: {e}"


def validate_email(email: str) -> Tuple[bool, Optional[str]]:
    """Basic email validation.

    Args:
        email: Email address to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email cannot be empty"

    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Invalid email format"

    return True, None


def validate_cidr(cidr: str) -> Tuple[bool, Optional[str]]:
    """Validate a CIDR network notation.

    Args:
        cidr: CIDR notation string (e.g., "192.168.1.0/24")

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not cidr:
        return False, "CIDR cannot be empty"

    try:
        ipaddress.ip_network(cidr, strict=False)
        return True, None
    except ValueError as e:
        return False, f"Invalid CIDR: {e}"
