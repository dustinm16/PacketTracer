"""Relay agents panel for viewing and managing connected agents."""

import time
import threading
from typing import Optional, List, Dict
from dataclasses import dataclass
from enum import Enum, auto
from rich.table import Table
from rich.panel import Panel
from rich.console import Group, RenderableType
from rich.columns import Columns
from rich.text import Text

from db.repositories.relay_repo import RelayRepository, AgentInfo
from utils.network import format_bytes


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        mins = int((seconds % 3600) / 60)
        return f"{hours}h {mins}m"
    else:
        days = int(seconds / 86400)
        hours = int((seconds % 86400) / 3600)
        return f"{days}d {hours}h"


def format_ago(timestamp: float) -> str:
    """Format timestamp as 'X ago'."""
    delta = time.time() - timestamp
    return format_duration(delta) + " ago"


class RelayInputMode(Enum):
    """Input modes for relay panel."""
    NORMAL = auto()
    DEPLOY_HOST = auto()
    DEPLOY_USER = auto()
    DEPLOY_KEY = auto()
    DEPLOY_NAME = auto()
    REGISTER_ID = auto()
    REGISTER_NAME = auto()
    REGISTER_HOST = auto()


@dataclass
class DeploymentState:
    """State for deployment input."""
    host: str = ""
    user: str = "root"
    ssh_key: str = "~/.ssh/id_rsa"
    name: str = ""
    port: int = 22


@dataclass
class RegistrationState:
    """State for manual registration."""
    agent_id: str = ""
    name: str = ""
    host: str = ""


class RelayPanel:
    """Panel displaying relay agent status and management controls."""

    def __init__(
        self,
        relay_repo: Optional[RelayRepository] = None,
        server_url: str = "wss://localhost:8765",
    ):
        self.relay_repo = relay_repo
        self.server_url = server_url
        self._selected_agent: Optional[str] = None
        self._agent_list: List[AgentInfo] = []

        # Input handling
        self.input_mode = RelayInputMode.NORMAL
        self.input_buffer = ""
        self.deploy_state = DeploymentState()
        self.register_state = RegistrationState()

        # Status messages
        self._status_message = ""
        self._status_timeout = 0

        # Deployment results
        self._last_deploy_result: Optional[Dict] = None
        self._deploying = False

        # Lazy load deployer
        self._deployer = None

    def _get_deployer(self):
        """Lazy load the deployer."""
        if self._deployer is None:
            try:
                from relay.deploy.deployer import AgentDeployer
                self._deployer = AgentDeployer(server_url=self.server_url)
            except ImportError:
                pass
        return self._deployer

    def set_repository(self, repo: RelayRepository) -> None:
        """Set the relay repository."""
        self.relay_repo = repo

    def set_server_url(self, url: str) -> None:
        """Set the relay server URL for deployments."""
        self.server_url = url
        self._deployer = None  # Reset deployer

    def select_agent(self, agent_id: str) -> None:
        """Select an agent to view details."""
        self._selected_agent = agent_id

    def clear_selection(self) -> None:
        """Clear agent selection."""
        self._selected_agent = None

    def _show_status(self, message: str, duration: float = 3.0) -> None:
        """Show a status message."""
        self._status_message = message
        self._status_timeout = time.time() + duration

    def _get_agents(self) -> List[AgentInfo]:
        """Get all agents from repository."""
        if not self.relay_repo:
            return []
        try:
            return self.relay_repo.get_all_agents()
        except Exception:
            return []

    def _get_status_style(self, agent: AgentInfo) -> str:
        """Get style for agent status."""
        if agent.status == "online" and agent.is_online:
            return "green"
        elif agent.status == "offline":
            return "yellow"
        elif agent.status == "error":
            return "red"
        elif agent.status == "revoked":
            return "dim red"
        elif agent.status == "registered":
            return "cyan"
        else:
            return "white"

    def _render_agent_list(self) -> Panel:
        """Render list of all agents."""
        agents = self._get_agents()
        self._agent_list = agents

        if not agents:
            content = Text()
            content.append("No agents registered\n\n", style="dim")
            content.append("Press ", style="dim")
            content.append("d", style="bold cyan")
            content.append(" to deploy a new agent via SSH\n", style="dim")
            content.append("Press ", style="dim")
            content.append("n", style="bold cyan")
            content.append(" to register an agent manually\n", style="dim")
            return Panel(
                content,
                title="[bold]Relay Agents[/bold]",
                border_style="blue"
            )

        table = Table(show_header=True, header_style="bold", box=None, expand=True)
        table.add_column("#", width=3)
        table.add_column("Name", style="cyan", no_wrap=True, max_width=15)
        table.add_column("Host", no_wrap=True, max_width=18)
        table.add_column("Status", width=10)
        table.add_column("Last Seen", width=12)
        table.add_column("OS", width=8)

        for idx, agent in enumerate(agents, 1):
            status_style = self._get_status_style(agent)
            status_text = f"[{status_style}]{agent.status.upper()}[/{status_style}]"

            os_info = agent.system_info.get("os_type", "?")[:8]
            last_seen = format_ago(agent.last_seen) if agent.last_seen else "never"
            row_style = "bold" if agent.agent_id == self._selected_agent else ""

            table.add_row(
                str(idx),
                agent.name or agent.agent_id[:12],
                agent.host[:18] if agent.host else "?",
                status_text,
                last_seen,
                os_info,
                style=row_style,
            )

        online_count = sum(1 for a in agents if a.is_online)
        summary = f"[green]{online_count}[/green] online / {len(agents)} total"

        return Panel(
            Group(table, Text(summary, style="dim")),
            title="[bold]Relay Agents[/bold]",
            border_style="blue"
        )

    def _render_agent_details(self) -> Panel:
        """Render details for selected agent."""
        if not self._selected_agent or not self.relay_repo:
            return Panel(
                "[dim]Select an agent (1-9) to view details[/dim]",
                title="[bold]Agent Details[/bold]",
                border_style="blue"
            )

        agent = self.relay_repo.get_agent(self._selected_agent)
        if not agent:
            return Panel(
                f"[red]Agent not found[/red]",
                title="[bold]Agent Details[/bold]",
                border_style="blue"
            )

        lines = []
        status_style = self._get_status_style(agent)

        lines.append(f"[bold]Agent ID:[/bold]     {agent.agent_id}")
        lines.append(f"[bold]Name:[/bold]         {agent.name}")
        lines.append(f"[bold]Host:[/bold]         {agent.host}")
        lines.append(f"[bold]Status:[/bold]       [{status_style}]{agent.status.upper()}[/{status_style}]")
        lines.append("")
        lines.append(f"[bold]Hardware ID:[/bold]  {agent.hardware_id[:16]}...")
        lines.append(f"[bold]Registered:[/bold]   {format_ago(agent.registered_at)}")
        lines.append(f"[bold]Last Seen:[/bold]    {format_ago(agent.last_seen)}")

        if agent.system_info:
            lines.append("")
            lines.append("[bold underline]System Info[/bold underline]")
            for key in ("hostname", "os_type", "arch", "agent_version"):
                if key in agent.system_info:
                    lines.append(f"  [cyan]{key}:[/cyan] {agent.system_info[key]}")

        return Panel(
            "\n".join(lines),
            title=f"[bold]Agent: {agent.name or agent.agent_id[:12]}[/bold]",
            border_style="green" if agent.is_online else "yellow"
        )

    def _render_metrics(self) -> Panel:
        """Render metrics for selected agent."""
        if not self._selected_agent or not self.relay_repo:
            return Panel(
                "[dim]No agent selected[/dim]",
                title="[bold]Metrics[/bold]",
                border_style="blue"
            )

        try:
            metrics = self.relay_repo.get_metrics(self._selected_agent, limit=10)
        except Exception:
            metrics = []

        if not metrics:
            return Panel(
                "[dim]No metrics data yet[/dim]",
                title="[bold]Metrics[/bold]",
                border_style="blue"
            )

        latest = metrics[0]

        def make_bar(percent, style):
            bar_len = int(20 * percent / 100)
            return f"[{style}]{'█' * bar_len}{'░' * (20 - bar_len)}[/{style}]"

        cpu_style = "green" if latest.cpu_percent < 50 else "yellow" if latest.cpu_percent < 80 else "red"
        mem_style = "green" if latest.memory_percent < 50 else "yellow" if latest.memory_percent < 80 else "red"
        disk_style = "green" if latest.disk_percent < 70 else "yellow" if latest.disk_percent < 90 else "red"

        lines = [
            f"[bold]CPU:[/bold]    {make_bar(latest.cpu_percent, cpu_style)} {latest.cpu_percent:5.1f}%",
            f"[bold]Memory:[/bold] {make_bar(latest.memory_percent, mem_style)} {latest.memory_percent:5.1f}%",
            f"[bold]Disk:[/bold]   {make_bar(latest.disk_percent, disk_style)} {latest.disk_percent:5.1f}%",
            "",
            f"[bold]Network RX:[/bold] {format_bytes(latest.network_rx_bytes)}",
            f"[bold]Network TX:[/bold] {format_bytes(latest.network_tx_bytes)}",
            "",
            f"[dim]Updated: {format_ago(latest.timestamp)}[/dim]",
        ]

        return Panel("\n".join(lines), title="[bold]Metrics[/bold]", border_style="blue")

    def _render_controls(self) -> Panel:
        """Render control panel with actions."""
        lines = []

        lines.append("[bold underline]Agent Management[/bold underline]")
        lines.append("")
        lines.append("[cyan]d[/cyan] Deploy new agent via SSH")
        lines.append("[cyan]n[/cyan] Register agent manually")
        lines.append("")

        if self._selected_agent:
            lines.append("[bold underline]Selected Agent[/bold underline]")
            lines.append("")
            lines.append("[cyan]x[/cyan] Revoke agent access")
            lines.append("[cyan]Del[/cyan] Delete agent")
            lines.append("")

        lines.append("[bold underline]View[/bold underline]")
        lines.append("")
        lines.append("[cyan]1-9[/cyan] Select agent")
        lines.append("[cyan]Esc[/cyan] Clear selection")
        lines.append("[cyan]r[/cyan] Refresh list")

        return Panel("\n".join(lines), title="[bold]Controls[/bold]", border_style="blue")

    def _render_deploy_form(self) -> Panel:
        """Render deployment input form."""
        lines = []
        lines.append("[bold]Deploy Agent via SSH[/bold]")
        lines.append("")

        # Show current field being edited
        fields = [
            ("Host", self.deploy_state.host, RelayInputMode.DEPLOY_HOST),
            ("User", self.deploy_state.user, RelayInputMode.DEPLOY_USER),
            ("SSH Key", self.deploy_state.ssh_key, RelayInputMode.DEPLOY_KEY),
            ("Name", self.deploy_state.name, RelayInputMode.DEPLOY_NAME),
        ]

        for label, value, mode in fields:
            if self.input_mode == mode:
                lines.append(f"[bold cyan]{label}:[/bold cyan] {self.input_buffer}█")
            else:
                display = value if value else "[dim]<empty>[/dim]"
                lines.append(f"[bold]{label}:[/bold] {display}")

        lines.append("")
        if self._deploying:
            lines.append("[yellow]Deploying...[/yellow]")
        else:
            lines.append("[dim]Tab=Next field, Enter=Deploy, Esc=Cancel[/dim]")

        return Panel("\n".join(lines), title="[bold yellow]New Deployment[/bold yellow]", border_style="yellow")

    def _render_register_form(self) -> Panel:
        """Render manual registration form."""
        lines = []
        lines.append("[bold]Register Agent Manually[/bold]")
        lines.append("")
        lines.append("[dim]Use this to register an agent you'll set up manually.[/dim]")
        lines.append("[dim]A token will be generated for the agent config.[/dim]")
        lines.append("")

        fields = [
            ("Agent ID", self.register_state.agent_id, RelayInputMode.REGISTER_ID),
            ("Name", self.register_state.name, RelayInputMode.REGISTER_NAME),
            ("Host", self.register_state.host, RelayInputMode.REGISTER_HOST),
        ]

        for label, value, mode in fields:
            if self.input_mode == mode:
                lines.append(f"[bold cyan]{label}:[/bold cyan] {self.input_buffer}█")
            else:
                display = value if value else "[dim]<empty>[/dim]"
                lines.append(f"[bold]{label}:[/bold] {display}")

        lines.append("")
        lines.append("[dim]Tab=Next field, Enter=Register, Esc=Cancel[/dim]")

        return Panel("\n".join(lines), title="[bold yellow]Manual Registration[/bold yellow]", border_style="yellow")

    def _render_result(self) -> Panel:
        """Render last deployment/registration result."""
        if not self._last_deploy_result:
            return Panel(
                "[dim]No recent operations[/dim]",
                title="[bold]Last Result[/bold]",
                border_style="blue"
            )

        result = self._last_deploy_result
        if result.get("success"):
            lines = [
                "[green]✓ Success[/green]",
                "",
                f"[bold]Agent ID:[/bold] {result.get('agent_id', 'N/A')}",
                f"[bold]Host:[/bold] {result.get('host', 'N/A')}",
            ]
            if result.get("token"):
                lines.append("")
                lines.append("[bold]Token:[/bold]")
                lines.append(f"[cyan]{result['token'][:20]}...[/cyan]")
                lines.append("")
                lines.append("[dim]Save this token for agent config![/dim]")
        else:
            lines = [
                "[red]✗ Failed[/red]",
                "",
                f"[bold]Error:[/bold] {result.get('error', 'Unknown error')}",
            ]

        return Panel("\n".join(lines), title="[bold]Last Result[/bold]", border_style="green" if result.get("success") else "red")

    def _render_status_bar(self) -> Text:
        """Render status bar with messages."""
        if self._status_message and time.time() < self._status_timeout:
            return Text.from_markup(self._status_message)
        return Text()

    def render(self) -> RenderableType:
        """Render the relay panel."""
        if not self.relay_repo:
            return Panel(
                "[yellow]Relay repository not initialized[/yellow]\n\n"
                "The database needs relay tables.\n"
                "Run schema migration if needed.",
                title="[bold]Relay Agents[/bold]",
                border_style="red"
            )

        elements = []

        # Show input form if in input mode
        if self.input_mode in (RelayInputMode.DEPLOY_HOST, RelayInputMode.DEPLOY_USER,
                                RelayInputMode.DEPLOY_KEY, RelayInputMode.DEPLOY_NAME):
            # Deploy form mode
            top_row = Columns([
                self._render_deploy_form(),
                self._render_result(),
            ], expand=True)
            elements.append(top_row)
            elements.append(self._render_status_bar())
            return Group(*elements)

        elif self.input_mode in (RelayInputMode.REGISTER_ID, RelayInputMode.REGISTER_NAME,
                                  RelayInputMode.REGISTER_HOST):
            # Register form mode
            top_row = Columns([
                self._render_register_form(),
                self._render_result(),
            ], expand=True)
            elements.append(top_row)
            elements.append(self._render_status_bar())
            return Group(*elements)

        # Normal mode - show agent list and details
        top_row = Columns([
            self._render_agent_list(),
            self._render_controls(),
        ], expand=True)
        elements.append(top_row)

        if self._selected_agent:
            bottom_row = Columns([
                self._render_agent_details(),
                self._render_metrics(),
                self._render_result(),
            ], expand=True)
        else:
            bottom_row = Columns([
                self._render_result(),
            ], expand=True)

        elements.append(bottom_row)

        # Status bar
        status = self._render_status_bar()
        if status:
            elements.append(status)

        return Group(*elements)

    def start_deploy_mode(self) -> None:
        """Enter deploy mode."""
        self.deploy_state = DeploymentState()
        self.input_mode = RelayInputMode.DEPLOY_HOST
        self.input_buffer = ""

    def start_register_mode(self) -> None:
        """Enter manual registration mode."""
        self.register_state = RegistrationState()
        self.input_mode = RelayInputMode.REGISTER_ID
        self.input_buffer = ""

    def cancel_input(self) -> None:
        """Cancel current input mode."""
        self.input_mode = RelayInputMode.NORMAL
        self.input_buffer = ""

    def _next_deploy_field(self) -> None:
        """Move to next deploy field."""
        # Save current field
        if self.input_mode == RelayInputMode.DEPLOY_HOST:
            self.deploy_state.host = self.input_buffer
            self.input_mode = RelayInputMode.DEPLOY_USER
            self.input_buffer = self.deploy_state.user
        elif self.input_mode == RelayInputMode.DEPLOY_USER:
            self.deploy_state.user = self.input_buffer
            self.input_mode = RelayInputMode.DEPLOY_KEY
            self.input_buffer = self.deploy_state.ssh_key
        elif self.input_mode == RelayInputMode.DEPLOY_KEY:
            self.deploy_state.ssh_key = self.input_buffer
            self.input_mode = RelayInputMode.DEPLOY_NAME
            self.input_buffer = self.deploy_state.name
        elif self.input_mode == RelayInputMode.DEPLOY_NAME:
            self.deploy_state.name = self.input_buffer
            # Wrap back to host
            self.input_mode = RelayInputMode.DEPLOY_HOST
            self.input_buffer = self.deploy_state.host

    def _next_register_field(self) -> None:
        """Move to next register field."""
        if self.input_mode == RelayInputMode.REGISTER_ID:
            self.register_state.agent_id = self.input_buffer
            self.input_mode = RelayInputMode.REGISTER_NAME
            self.input_buffer = self.register_state.name
        elif self.input_mode == RelayInputMode.REGISTER_NAME:
            self.register_state.name = self.input_buffer
            self.input_mode = RelayInputMode.REGISTER_HOST
            self.input_buffer = self.register_state.host
        elif self.input_mode == RelayInputMode.REGISTER_HOST:
            self.register_state.host = self.input_buffer
            # Wrap back
            self.input_mode = RelayInputMode.REGISTER_ID
            self.input_buffer = self.register_state.agent_id

    def execute_deploy(self) -> None:
        """Execute the deployment."""
        # Save current field
        if self.input_mode == RelayInputMode.DEPLOY_HOST:
            self.deploy_state.host = self.input_buffer
        elif self.input_mode == RelayInputMode.DEPLOY_USER:
            self.deploy_state.user = self.input_buffer
        elif self.input_mode == RelayInputMode.DEPLOY_KEY:
            self.deploy_state.ssh_key = self.input_buffer
        elif self.input_mode == RelayInputMode.DEPLOY_NAME:
            self.deploy_state.name = self.input_buffer

        if not self.deploy_state.host:
            self._show_status("[red]Host is required[/red]")
            return

        deployer = self._get_deployer()
        if not deployer:
            self._show_status("[red]Deployer not available[/red]")
            return

        self._deploying = True
        self._show_status("[yellow]Deploying agent...[/yellow]", 30)

        def do_deploy():
            try:
                from relay.deploy.deployer import DeploymentTarget
                target = DeploymentTarget(
                    host=self.deploy_state.host,
                    user=self.deploy_state.user,
                    ssh_key=self.deploy_state.ssh_key if self.deploy_state.ssh_key else None,
                    port=self.deploy_state.port,
                )
                result = deployer.deploy(target)

                if result.success:
                    # Register in database
                    if self.relay_repo:
                        self.relay_repo.register_agent(
                            agent_id=result.agent_id,
                            name=self.deploy_state.name or result.agent_id,
                            host=self.deploy_state.host,
                            hardware_id=result.hardware_id,
                            token=result.token,
                        )

                    self._last_deploy_result = {
                        "success": True,
                        "agent_id": result.agent_id,
                        "host": result.host,
                        "token": result.token,
                        "message": result.message,
                    }
                    self._show_status("[green]Agent deployed successfully![/green]")
                else:
                    self._last_deploy_result = {
                        "success": False,
                        "host": result.host,
                        "error": result.error or result.message,
                    }
                    self._show_status(f"[red]Deployment failed: {result.error}[/red]")
            except Exception as e:
                self._last_deploy_result = {
                    "success": False,
                    "error": str(e),
                }
                self._show_status(f"[red]Error: {e}[/red]")
            finally:
                self._deploying = False
                self.input_mode = RelayInputMode.NORMAL
                self.input_buffer = ""

        # Run in background thread
        thread = threading.Thread(target=do_deploy, daemon=True)
        thread.start()

    def execute_register(self) -> None:
        """Execute manual registration."""
        # Save current field
        if self.input_mode == RelayInputMode.REGISTER_ID:
            self.register_state.agent_id = self.input_buffer
        elif self.input_mode == RelayInputMode.REGISTER_NAME:
            self.register_state.name = self.input_buffer
        elif self.input_mode == RelayInputMode.REGISTER_HOST:
            self.register_state.host = self.input_buffer

        if not self.register_state.agent_id:
            self._show_status("[red]Agent ID is required[/red]")
            return

        if not self.relay_repo:
            self._show_status("[red]Repository not available[/red]")
            return

        try:
            # Generate a hardware ID placeholder (user will need real one from agent)
            import secrets
            placeholder_hw_id = secrets.token_hex(16)

            agent_id, token = self.relay_repo.register_agent(
                agent_id=self.register_state.agent_id,
                name=self.register_state.name or self.register_state.agent_id,
                host=self.register_state.host or "pending",
                hardware_id=placeholder_hw_id,
            )

            self._last_deploy_result = {
                "success": True,
                "agent_id": agent_id,
                "host": self.register_state.host,
                "token": token,
            }
            self._show_status("[green]Agent registered! Copy the token for agent config.[/green]")

        except Exception as e:
            self._last_deploy_result = {
                "success": False,
                "error": str(e),
            }
            self._show_status(f"[red]Registration failed: {e}[/red]")

        self.input_mode = RelayInputMode.NORMAL
        self.input_buffer = ""

    def revoke_selected_agent(self) -> bool:
        """Revoke the selected agent's access."""
        if not self._selected_agent or not self.relay_repo:
            return False

        try:
            if self.relay_repo.revoke_agent(self._selected_agent):
                self._show_status("[yellow]Agent access revoked[/yellow]")
                return True
            else:
                self._show_status("[red]Failed to revoke agent[/red]")
                return False
        except Exception as e:
            self._show_status(f"[red]Error: {e}[/red]")
            return False

    def delete_selected_agent(self) -> bool:
        """Delete the selected agent."""
        if not self._selected_agent or not self.relay_repo:
            return False

        try:
            if self.relay_repo.delete_agent(self._selected_agent):
                self._show_status("[yellow]Agent deleted[/yellow]")
                self._selected_agent = None
                return True
            else:
                self._show_status("[red]Failed to delete agent[/red]")
                return False
        except Exception as e:
            self._show_status(f"[red]Error: {e}[/red]")
            return False

    def handle_key(self, key: str) -> bool:
        """Handle keyboard input for the panel.

        Returns:
            True if key was handled, False otherwise
        """
        # Handle input modes
        if self.input_mode != RelayInputMode.NORMAL:
            return self._handle_input_key(key)

        # Normal mode - agent selection
        if key.isdigit() and 1 <= int(key) <= len(self._agent_list):
            idx = int(key) - 1
            self._selected_agent = self._agent_list[idx].agent_id
            return True
        elif key == "d":
            self.start_deploy_mode()
            return True
        elif key == "n":
            self.start_register_mode()
            return True
        elif key == "x" and self._selected_agent:
            self.revoke_selected_agent()
            return True
        elif key == "r":
            self._agent_list = self._get_agents()
            self._show_status("[cyan]Agent list refreshed[/cyan]", 1.0)
            return True

        return False

    def _handle_input_key(self, key: str) -> bool:
        """Handle key in input mode."""
        # This is called character by character from the input handler
        if len(key) == 1 and key.isprintable():
            self.input_buffer += key
            return True
        return False

    def handle_special_key(self, key_name: str) -> bool:
        """Handle special keys (escape, enter, tab, backspace).

        Args:
            key_name: Name of key ("escape", "enter", "tab", "backspace", "delete")

        Returns:
            True if handled
        """
        if self.input_mode == RelayInputMode.NORMAL:
            if key_name == "escape":
                self.clear_selection()
                return True
            elif key_name == "delete" and self._selected_agent:
                self.delete_selected_agent()
                return True
            return False

        # Input mode handling
        if key_name == "escape":
            self.cancel_input()
            return True
        elif key_name == "backspace":
            self.input_buffer = self.input_buffer[:-1]
            return True
        elif key_name == "tab":
            if self.input_mode in (RelayInputMode.DEPLOY_HOST, RelayInputMode.DEPLOY_USER,
                                    RelayInputMode.DEPLOY_KEY, RelayInputMode.DEPLOY_NAME):
                self._next_deploy_field()
            else:
                self._next_register_field()
            return True
        elif key_name == "enter":
            if self.input_mode in (RelayInputMode.DEPLOY_HOST, RelayInputMode.DEPLOY_USER,
                                    RelayInputMode.DEPLOY_KEY, RelayInputMode.DEPLOY_NAME):
                self.execute_deploy()
            else:
                self.execute_register()
            return True

        return False

    def is_in_input_mode(self) -> bool:
        """Check if panel is in input mode."""
        return self.input_mode != RelayInputMode.NORMAL
