#!/usr/bin/env python3
"""Relay agent for remote network monitoring.

This agent runs on remote hosts and sends metrics/flows back to the
PacketTracer control panel via TLS-encrypted WebSocket.

Security features:
- Hardware-bound token (validates MAC address or machine-id)
- TLS encrypted communication
- Heartbeat monitoring
"""

import argparse
import asyncio
import hashlib
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

# Agent version
AGENT_VERSION = "1.0.0"

# Default config
DEFAULT_CONFIG = {
    "heartbeat_interval": 30,
    "metrics_interval": 60,
    "flows_interval": 30,
    "capture_enabled": False,
    "capture_interface": None,
    "capture_filter": "ip",
}


@dataclass
class AgentConfig:
    """Agent configuration."""
    agent_id: str
    token: str
    server_url: str
    hardware_id: str
    heartbeat_interval: int = 30
    metrics_interval: int = 60
    flows_interval: int = 30
    capture_enabled: bool = False
    capture_interface: Optional[str] = None
    capture_filter: str = "ip"
    verify_ssl: bool = True

    @classmethod
    def from_file(cls, path: str) -> "AgentConfig":
        """Load config from JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls(**data)

    def to_file(self, path: str) -> None:
        """Save config to JSON file."""
        with open(path, 'w') as f:
            json.dump(asdict(self), f, indent=2)
        # Secure the file
        os.chmod(path, 0o600)


class HardwareID:
    """Hardware identification utilities."""

    @staticmethod
    def get_machine_id() -> Optional[str]:
        """Get the machine ID (Linux/systemd)."""
        paths = [
            "/etc/machine-id",
            "/var/lib/dbus/machine-id",
        ]
        for path in paths:
            try:
                with open(path) as f:
                    return f.read().strip()
            except FileNotFoundError:
                continue
        return None

    @staticmethod
    def get_mac_address() -> Optional[str]:
        """Get the primary MAC address."""
        try:
            # Try to get from /sys/class/net
            net_path = Path("/sys/class/net")
            if net_path.exists():
                for iface in net_path.iterdir():
                    if iface.name == "lo":
                        continue
                    addr_file = iface / "address"
                    if addr_file.exists():
                        mac = addr_file.read_text().strip()
                        if mac and mac != "00:00:00:00:00:00":
                            return mac.replace(":", "").lower()
        except Exception:
            pass

        # Fallback: use uuid.getnode()
        try:
            import uuid
            mac = uuid.getnode()
            return format(mac, '012x')
        except Exception:
            return None

    @staticmethod
    def get_hardware_id() -> str:
        """Get a stable hardware identifier.

        Combines machine-id and MAC address for uniqueness.
        """
        machine_id = HardwareID.get_machine_id() or ""
        mac = HardwareID.get_mac_address() or ""

        # Create combined hash
        combined = f"{machine_id}:{mac}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    @staticmethod
    def verify_hardware_id(expected: str) -> bool:
        """Verify current hardware matches expected ID."""
        current = HardwareID.get_hardware_id()
        return current == expected


class SystemMetrics:
    """System metrics collection."""

    @staticmethod
    def get_cpu_usage() -> float:
        """Get CPU usage percentage."""
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            values = [int(x) for x in line.split()[1:8]]
            idle = values[3]
            total = sum(values)

            # Read again after short delay
            time.sleep(0.1)
            with open("/proc/stat") as f:
                line = f.readline()
            values2 = [int(x) for x in line.split()[1:8]]
            idle2 = values2[3]
            total2 = sum(values2)

            idle_delta = idle2 - idle
            total_delta = total2 - total

            if total_delta == 0:
                return 0.0
            return (1.0 - idle_delta / total_delta) * 100
        except Exception:
            return 0.0

    @staticmethod
    def get_memory_usage() -> Dict[str, int]:
        """Get memory usage in bytes."""
        try:
            with open("/proc/meminfo") as f:
                lines = f.readlines()

            mem = {}
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    value = int(parts[1]) * 1024  # Convert from kB
                    mem[key] = value

            total = mem.get("MemTotal", 0)
            available = mem.get("MemAvailable", mem.get("MemFree", 0))
            used = total - available

            return {
                "total": total,
                "used": used,
                "available": available,
                "percent": (used / total * 100) if total > 0 else 0,
            }
        except Exception:
            return {"total": 0, "used": 0, "available": 0, "percent": 0}

    @staticmethod
    def get_disk_usage(path: str = "/") -> Dict[str, int]:
        """Get disk usage for a path."""
        try:
            stat = os.statvfs(path)
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bfree * stat.f_frsize
            used = total - free
            return {
                "total": total,
                "used": used,
                "free": free,
                "percent": (used / total * 100) if total > 0 else 0,
            }
        except Exception:
            return {"total": 0, "used": 0, "free": 0, "percent": 0}

    @staticmethod
    def get_network_stats() -> Dict[str, Dict[str, int]]:
        """Get network interface statistics."""
        stats = {}
        try:
            with open("/proc/net/dev") as f:
                lines = f.readlines()[2:]  # Skip headers

            for line in lines:
                parts = line.split()
                iface = parts[0].rstrip(":")
                if iface == "lo":
                    continue
                stats[iface] = {
                    "rx_bytes": int(parts[1]),
                    "rx_packets": int(parts[2]),
                    "tx_bytes": int(parts[9]),
                    "tx_packets": int(parts[10]),
                }
        except Exception:
            pass
        return stats

    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Get system information."""
        return {
            "hostname": socket.gethostname(),
            "os_type": platform.system().lower(),
            "os_version": platform.release(),
            "python_version": platform.python_version(),
            "agent_version": AGENT_VERSION,
            "arch": platform.machine(),
        }

    @staticmethod
    def get_all_metrics() -> Dict[str, Any]:
        """Get all system metrics."""
        return {
            "cpu": {"percent": SystemMetrics.get_cpu_usage()},
            "memory": SystemMetrics.get_memory_usage(),
            "disk": SystemMetrics.get_disk_usage(),
            "network": SystemMetrics.get_network_stats(),
            "timestamp": time.time(),
        }


class RelayAgent:
    """Relay agent that connects to PacketTracer control panel."""

    def __init__(self, config: AgentConfig):
        if not HAS_WEBSOCKETS:
            raise ImportError("websockets package required: pip install websockets")

        self.config = config
        self._running = False
        self._websocket = None
        self._session_token: Optional[str] = None
        self._last_heartbeat = 0
        self._last_metrics = 0
        self._reconnect_delay = 5

        # Verify hardware ID on startup
        if not HardwareID.verify_hardware_id(config.hardware_id):
            raise RuntimeError(
                f"Hardware ID mismatch! This agent is bound to a different machine. "
                f"Expected: {config.hardware_id}, Got: {HardwareID.get_hardware_id()}"
            )

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for TLS connection."""
        if self.config.server_url.startswith("wss://"):
            context = ssl.create_default_context()
            if not self.config.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            return context
        return None

    async def _send_message(self, msg_type: str, payload: Dict) -> None:
        """Send a message to the server."""
        if not self._websocket:
            return

        message = json.dumps({
            "type": msg_type,
            "timestamp": time.time(),
            "payload": payload,
        })
        await self._websocket.send(message)

    async def _authenticate(self) -> bool:
        """Authenticate with the server."""
        try:
            await self._send_message("auth_request", {
                "agent_id": self.config.agent_id,
                "token": self.config.token,
                "hardware_id": self.config.hardware_id,
                "system_info": SystemMetrics.get_system_info(),
            })

            # Wait for response
            response = await asyncio.wait_for(
                self._websocket.recv(),
                timeout=10,
            )

            data = json.loads(response)
            if data.get("type") == "auth_response":
                payload = data.get("payload", {})
                if payload.get("success"):
                    self._session_token = payload.get("session_token")
                    print(f"Authenticated with server")
                    return True
                else:
                    print(f"Authentication failed: {payload.get('message')}")
                    return False
            return False
        except Exception as e:
            print(f"Authentication error: {e}")
            return False

    async def _send_heartbeat(self) -> None:
        """Send heartbeat to server."""
        await self._send_message("heartbeat", {
            "agent_id": self.config.agent_id,
            "status": {
                "uptime": time.time() - self._last_heartbeat,
                "capture_enabled": self.config.capture_enabled,
            },
        })
        self._last_heartbeat = time.time()

    async def _send_metrics(self) -> None:
        """Send system metrics to server."""
        metrics = SystemMetrics.get_all_metrics()
        await self._send_message("metrics", {
            "agent_id": self.config.agent_id,
            "metric_type": "system",
            "data": metrics,
        })
        self._last_metrics = time.time()

    async def _handle_message(self, message: str) -> None:
        """Handle incoming message from server."""
        try:
            data = json.loads(message)
            msg_type = data.get("type")

            if msg_type == "heartbeat_ack":
                pass  # Heartbeat acknowledged
            elif msg_type == "cmd_start_capture":
                self.config.capture_enabled = True
                print("Capture enabled by server")
            elif msg_type == "cmd_stop_capture":
                self.config.capture_enabled = False
                print("Capture disabled by server")
            elif msg_type == "cmd_update_config":
                payload = data.get("payload", {})
                for key, value in payload.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                print(f"Config updated: {payload}")
            elif msg_type == "error":
                payload = data.get("payload", {})
                print(f"Server error: {payload.get('message')}")

        except Exception as e:
            print(f"Error handling message: {e}")

    async def _run_loop(self) -> None:
        """Main agent loop."""
        ssl_context = self._create_ssl_context()

        while self._running:
            try:
                async with websockets.connect(
                    self.config.server_url,
                    ssl=ssl_context,
                ) as websocket:
                    self._websocket = websocket
                    self._reconnect_delay = 5  # Reset on successful connect

                    # Authenticate
                    if not await self._authenticate():
                        await asyncio.sleep(30)
                        continue

                    # Main loop
                    while self._running:
                        # Check for incoming messages (non-blocking)
                        try:
                            message = await asyncio.wait_for(
                                websocket.recv(),
                                timeout=1.0,
                            )
                            await self._handle_message(message)
                        except asyncio.TimeoutError:
                            pass

                        # Send heartbeat
                        now = time.time()
                        if now - self._last_heartbeat >= self.config.heartbeat_interval:
                            await self._send_heartbeat()

                        # Send metrics
                        if now - self._last_metrics >= self.config.metrics_interval:
                            await self._send_metrics()

            except websockets.exceptions.ConnectionClosed:
                print("Connection closed, reconnecting...")
            except Exception as e:
                print(f"Connection error: {e}")

            if self._running:
                print(f"Reconnecting in {self._reconnect_delay}s...")
                await asyncio.sleep(self._reconnect_delay)
                self._reconnect_delay = min(self._reconnect_delay * 2, 300)

    def run(self) -> None:
        """Run the agent (blocking)."""
        self._running = True
        print(f"Starting relay agent {self.config.agent_id}")
        print(f"Connecting to {self.config.server_url}")

        try:
            asyncio.run(self._run_loop())
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            self._running = False

    def stop(self) -> None:
        """Stop the agent."""
        self._running = False


def main():
    """Main entry point for the relay agent."""
    parser = argparse.ArgumentParser(
        description="PacketTracer Relay Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to config file",
        default="~/.packettracer/agent.json",
    )
    parser.add_argument(
        "--server",
        help="Server WebSocket URL (wss://host:port)",
    )
    parser.add_argument(
        "--agent-id",
        help="Agent ID",
    )
    parser.add_argument(
        "--token",
        help="Authentication token",
    )
    parser.add_argument(
        "--hardware-id",
        help="Expected hardware ID (for verification)",
    )
    parser.add_argument(
        "--show-hardware-id",
        action="store_true",
        help="Show this machine's hardware ID and exit",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    args = parser.parse_args()

    # Show hardware ID and exit
    if args.show_hardware_id:
        print(f"Hardware ID: {HardwareID.get_hardware_id()}")
        print(f"Machine ID: {HardwareID.get_machine_id() or 'N/A'}")
        print(f"MAC Address: {HardwareID.get_mac_address() or 'N/A'}")
        sys.exit(0)

    # Load or create config
    config_path = Path(args.config).expanduser()

    if config_path.exists():
        try:
            config = AgentConfig.from_file(str(config_path))
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)
    else:
        # Require command line args if no config
        if not all([args.server, args.agent_id, args.token]):
            print("No config file found. Please provide --server, --agent-id, and --token")
            sys.exit(1)

        config = AgentConfig(
            agent_id=args.agent_id,
            token=args.token,
            server_url=args.server,
            hardware_id=args.hardware_id or HardwareID.get_hardware_id(),
            verify_ssl=not args.no_verify_ssl,
        )

        # Save config
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config.to_file(str(config_path))
        print(f"Config saved to {config_path}")

    # Override from command line
    if args.server:
        config.server_url = args.server
    if args.no_verify_ssl:
        config.verify_ssl = False

    # Run agent
    agent = RelayAgent(config)
    agent.run()


if __name__ == "__main__":
    main()
