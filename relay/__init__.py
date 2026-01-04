"""Relay agent system for distributed network monitoring.

This module provides:
- RelayAgent: Hardware-bound agent that runs on remote hosts
- RelayServer: WebSocket server for agent communication
- Deployment tools: SSH/SCP based agent distribution

Security:
- TLS encrypted WebSocket communications
- Hardware-bound agent tokens (MAC/machine-id)
- Token-based authentication
"""

from .server.relay_server import RelayServer
from .server.protocol import RelayProtocol, MessageType
from .deploy.deployer import AgentDeployer, DeploymentTarget, DeploymentResult

__all__ = [
    "RelayServer",
    "RelayProtocol",
    "MessageType",
    "AgentDeployer",
    "DeploymentTarget",
    "DeploymentResult",
]
