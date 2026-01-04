#!/usr/bin/env python3
"""Agent deployment via SSH/SCP.

Handles secure deployment of relay agents to remote hosts.
"""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple


@dataclass
class DeploymentTarget:
    """Target host for agent deployment."""
    host: str
    user: str
    port: int = 22
    ssh_key: Optional[str] = None
    password: Optional[str] = None  # Not recommended, use ssh_key
    install_path: str = "/opt/packettracer-agent"
    python_path: str = "/usr/bin/python3"

    @property
    def ssh_dest(self) -> str:
        """Get SSH destination string."""
        return f"{self.user}@{self.host}"


@dataclass
class DeploymentResult:
    """Result of a deployment operation."""
    success: bool
    host: str
    agent_id: str
    token: str
    hardware_id: str
    message: str
    error: Optional[str] = None


class AgentDeployer:
    """Deploy relay agents to remote hosts via SSH/SCP."""

    AGENT_FILES = [
        "relay/agent/agent.py",
        "relay/agent/__init__.py",
    ]

    def __init__(
        self,
        server_url: str,
        package_dir: Optional[str] = None,
        ssh_options: Optional[List[str]] = None,
    ):
        """Initialize deployer.

        Args:
            server_url: WebSocket URL of the relay server (wss://host:port)
            package_dir: Directory containing packettracer package
            ssh_options: Additional SSH options
        """
        self.server_url = server_url
        self.package_dir = package_dir or self._find_package_dir()
        self.ssh_options = ssh_options or [
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
        ]

    def _find_package_dir(self) -> str:
        """Find the packettracer package directory."""
        # Try relative to this file
        deploy_dir = Path(__file__).parent
        package_dir = deploy_dir.parent.parent
        if (package_dir / "relay" / "agent" / "agent.py").exists():
            return str(package_dir)
        raise RuntimeError("Could not find packettracer package directory")

    def _build_ssh_cmd(self, target: DeploymentTarget) -> List[str]:
        """Build base SSH command."""
        cmd = ["ssh"]
        cmd.extend(self.ssh_options)
        cmd.extend(["-p", str(target.port)])
        if target.ssh_key:
            cmd.extend(["-i", target.ssh_key])
        cmd.append(target.ssh_dest)
        return cmd

    def _build_scp_cmd(self, target: DeploymentTarget) -> List[str]:
        """Build base SCP command."""
        cmd = ["scp"]
        cmd.extend(self.ssh_options)
        cmd.extend(["-P", str(target.port)])
        if target.ssh_key:
            cmd.extend(["-i", target.ssh_key])
        return cmd

    def _run_ssh(
        self,
        target: DeploymentTarget,
        command: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run command on remote host."""
        cmd = self._build_ssh_cmd(target)
        cmd.append(command)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
        )

    def _run_scp(
        self,
        target: DeploymentTarget,
        local_path: str,
        remote_path: str,
        recursive: bool = False,
    ) -> subprocess.CompletedProcess:
        """Copy files to remote host."""
        cmd = self._build_scp_cmd(target)
        if recursive:
            cmd.append("-r")
        cmd.append(local_path)
        cmd.append(f"{target.ssh_dest}:{remote_path}")
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )

    def test_connection(self, target: DeploymentTarget) -> Tuple[bool, str]:
        """Test SSH connection to target.

        Returns:
            Tuple of (success, message)
        """
        try:
            result = self._run_ssh(target, "echo 'connection_ok'")
            if "connection_ok" in result.stdout:
                return True, "Connection successful"
            return False, f"Unexpected output: {result.stdout}"
        except subprocess.CalledProcessError as e:
            return False, f"SSH error: {e.stderr}"
        except Exception as e:
            return False, f"Error: {e}"

    def get_remote_hardware_id(self, target: DeploymentTarget) -> Optional[str]:
        """Get hardware ID from remote host.

        Returns:
            Hardware ID string or None on failure
        """
        # Python script to get hardware ID
        script = '''
import hashlib
import os
from pathlib import Path

def get_machine_id():
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            return open(path).read().strip()
        except:
            pass
    return ""

def get_mac():
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
    import uuid
    return format(uuid.getnode(), "012x")

combined = f"{get_machine_id()}:{get_mac()}"
print(hashlib.sha256(combined.encode()).hexdigest()[:32])
'''
        try:
            result = self._run_ssh(
                target,
                f'{target.python_path} -c "{script}"'
            )
            hw_id = result.stdout.strip()
            if len(hw_id) == 32:
                return hw_id
            return None
        except Exception:
            return None

    def generate_agent_credentials(self) -> Tuple[str, str]:
        """Generate agent ID and token.

        Returns:
            Tuple of (agent_id, token)
        """
        agent_id = f"agent-{secrets.token_hex(4)}"
        token = secrets.token_urlsafe(32)
        return agent_id, token

    def create_agent_package(
        self,
        agent_id: str,
        token: str,
        hardware_id: str,
        output_dir: Optional[str] = None,
    ) -> str:
        """Create deployable agent package.

        Args:
            agent_id: Agent identifier
            token: Authentication token
            hardware_id: Expected hardware ID
            output_dir: Directory for package (uses temp if None)

        Returns:
            Path to package directory
        """
        if output_dir:
            pkg_dir = Path(output_dir)
            pkg_dir.mkdir(parents=True, exist_ok=True)
        else:
            pkg_dir = Path(tempfile.mkdtemp(prefix="pt-agent-"))

        # Copy agent files
        for rel_path in self.AGENT_FILES:
            src = Path(self.package_dir) / rel_path
            dst = pkg_dir / Path(rel_path).name
            shutil.copy2(src, dst)

        # Create config file
        config = {
            "agent_id": agent_id,
            "token": token,
            "server_url": self.server_url,
            "hardware_id": hardware_id,
            "heartbeat_interval": 30,
            "metrics_interval": 60,
            "flows_interval": 30,
            "capture_enabled": False,
            "capture_interface": None,
            "capture_filter": "ip",
            "verify_ssl": True,
        }

        config_path = pkg_dir / "agent_config.json"
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        # Create systemd service file
        service_content = f'''[Unit]
Description=PacketTracer Relay Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/packettracer-agent
ExecStart=/usr/bin/python3 /opt/packettracer-agent/agent.py -c /opt/packettracer-agent/agent_config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
'''
        service_path = pkg_dir / "packettracer-agent.service"
        with open(service_path, 'w') as f:
            f.write(service_content)

        # Create install script
        install_script = '''#!/bin/bash
set -e

INSTALL_DIR="/opt/packettracer-agent"

# Create install directory
mkdir -p "$INSTALL_DIR"

# Copy files
cp agent.py "$INSTALL_DIR/"
cp agent_config.json "$INSTALL_DIR/"
chmod 600 "$INSTALL_DIR/agent_config.json"

# Install systemd service
cp packettracer-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable packettracer-agent
systemctl start packettracer-agent

echo "Agent installed and started successfully"
systemctl status packettracer-agent --no-pager
'''
        install_path = pkg_dir / "install.sh"
        with open(install_path, 'w') as f:
            f.write(install_script)
        os.chmod(install_path, 0o755)

        return str(pkg_dir)

    def deploy(
        self,
        target: DeploymentTarget,
        agent_id: Optional[str] = None,
        token: Optional[str] = None,
    ) -> DeploymentResult:
        """Deploy agent to target host.

        Args:
            target: Deployment target
            agent_id: Agent ID (generated if not provided)
            token: Auth token (generated if not provided)

        Returns:
            DeploymentResult with status and credentials
        """
        # Test connection first
        connected, msg = self.test_connection(target)
        if not connected:
            return DeploymentResult(
                success=False,
                host=target.host,
                agent_id="",
                token="",
                hardware_id="",
                message="Connection failed",
                error=msg,
            )

        # Get hardware ID
        hardware_id = self.get_remote_hardware_id(target)
        if not hardware_id:
            return DeploymentResult(
                success=False,
                host=target.host,
                agent_id="",
                token="",
                hardware_id="",
                message="Failed to get hardware ID",
                error="Could not retrieve hardware ID from remote host",
            )

        # Generate credentials if not provided
        if not agent_id or not token:
            agent_id, token = self.generate_agent_credentials()

        try:
            # Create package
            pkg_dir = self.create_agent_package(agent_id, token, hardware_id)

            # Create remote directory
            self._run_ssh(target, f"sudo mkdir -p {target.install_path}")

            # Copy package files
            self._run_scp(target, f"{pkg_dir}/*", f"/tmp/pt-agent/", recursive=False)

            # Actually, SCP doesn't like glob patterns well, let's do it file by file
            self._run_ssh(target, "mkdir -p /tmp/pt-agent")

            for f in Path(pkg_dir).iterdir():
                self._run_scp(target, str(f), "/tmp/pt-agent/")

            # Run install script
            result = self._run_ssh(
                target,
                "cd /tmp/pt-agent && sudo bash install.sh",
                check=False,
            )

            # Cleanup temp files
            self._run_ssh(target, "rm -rf /tmp/pt-agent", check=False)
            shutil.rmtree(pkg_dir, ignore_errors=True)

            if result.returncode != 0:
                return DeploymentResult(
                    success=False,
                    host=target.host,
                    agent_id=agent_id,
                    token=token,
                    hardware_id=hardware_id,
                    message="Installation failed",
                    error=result.stderr or result.stdout,
                )

            return DeploymentResult(
                success=True,
                host=target.host,
                agent_id=agent_id,
                token=token,
                hardware_id=hardware_id,
                message="Agent deployed successfully",
            )

        except Exception as e:
            return DeploymentResult(
                success=False,
                host=target.host,
                agent_id=agent_id or "",
                token=token or "",
                hardware_id=hardware_id,
                message="Deployment error",
                error=str(e),
            )

    def check_status(self, target: DeploymentTarget) -> Dict[str, Any]:
        """Check agent status on remote host.

        Returns:
            Status dictionary with service state and info
        """
        try:
            result = self._run_ssh(
                target,
                "systemctl is-active packettracer-agent 2>/dev/null || echo 'inactive'",
                check=False,
            )
            active = result.stdout.strip()

            result = self._run_ssh(
                target,
                "systemctl show packettracer-agent --property=ActiveState,SubState,MainPID 2>/dev/null || true",
                check=False,
            )

            props = {}
            for line in result.stdout.strip().split('\n'):
                if '=' in line:
                    k, v = line.split('=', 1)
                    props[k] = v

            return {
                "host": target.host,
                "running": active == "active",
                "active_state": props.get("ActiveState", "unknown"),
                "sub_state": props.get("SubState", "unknown"),
                "pid": props.get("MainPID", "0"),
            }
        except Exception as e:
            return {
                "host": target.host,
                "running": False,
                "error": str(e),
            }

    def stop_agent(self, target: DeploymentTarget) -> Tuple[bool, str]:
        """Stop agent on remote host."""
        try:
            self._run_ssh(target, "sudo systemctl stop packettracer-agent")
            return True, "Agent stopped"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to stop: {e.stderr}"

    def start_agent(self, target: DeploymentTarget) -> Tuple[bool, str]:
        """Start agent on remote host."""
        try:
            self._run_ssh(target, "sudo systemctl start packettracer-agent")
            return True, "Agent started"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to start: {e.stderr}"

    def restart_agent(self, target: DeploymentTarget) -> Tuple[bool, str]:
        """Restart agent on remote host."""
        try:
            self._run_ssh(target, "sudo systemctl restart packettracer-agent")
            return True, "Agent restarted"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to restart: {e.stderr}"

    def uninstall(self, target: DeploymentTarget) -> Tuple[bool, str]:
        """Uninstall agent from remote host."""
        try:
            commands = [
                "sudo systemctl stop packettracer-agent 2>/dev/null || true",
                "sudo systemctl disable packettracer-agent 2>/dev/null || true",
                "sudo rm -f /etc/systemd/system/packettracer-agent.service",
                "sudo systemctl daemon-reload",
                f"sudo rm -rf {target.install_path}",
            ]
            self._run_ssh(target, " && ".join(commands))
            return True, "Agent uninstalled"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to uninstall: {e.stderr}"

    def get_logs(
        self,
        target: DeploymentTarget,
        lines: int = 50,
    ) -> str:
        """Get agent logs from remote host."""
        try:
            result = self._run_ssh(
                target,
                f"sudo journalctl -u packettracer-agent -n {lines} --no-pager",
                check=False,
            )
            return result.stdout
        except Exception as e:
            return f"Error getting logs: {e}"
