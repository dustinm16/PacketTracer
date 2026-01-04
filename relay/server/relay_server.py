"""WebSocket relay server for agent communication."""

import asyncio
import hashlib
import json
import secrets
import ssl
import time
import threading
from pathlib import Path
from typing import Dict, Optional, Set, Callable, Any, TYPE_CHECKING
from dataclasses import dataclass, field

try:
    import websockets
    from websockets.server import serve, WebSocketServerProtocol
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    WebSocketServerProtocol = Any

from .protocol import RelayMessage, MessageType, RelayProtocol
from config import (
    RELAY_SERVER_HOST,
    RELAY_SERVER_PORT,
    RELAY_SERVER_CERT_FILE,
    RELAY_SERVER_KEY_FILE,
)

if TYPE_CHECKING:
    from db.connection import ConnectionPool
    from db.writer import DatabaseWriter


@dataclass
class ConnectedAgent:
    """Represents a connected relay agent."""
    agent_id: str
    hardware_id: str
    websocket: Any  # WebSocketServerProtocol
    ip_address: str
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    session_token: str = ""
    system_info: Dict[str, str] = field(default_factory=dict)
    authenticated: bool = False


class RelayServer:
    """WebSocket server for relay agent communication.

    Features:
    - TLS encrypted connections
    - Token-based authentication with hardware binding
    - Heartbeat monitoring
    - Message routing to database
    """

    def __init__(
        self,
        host: str = RELAY_SERVER_HOST,
        port: int = RELAY_SERVER_PORT,
        pool: Optional["ConnectionPool"] = None,
        writer: Optional["DatabaseWriter"] = None,
        cert_file: Optional[str] = RELAY_SERVER_CERT_FILE,
        key_file: Optional[str] = RELAY_SERVER_KEY_FILE,
    ):
        if not HAS_WEBSOCKETS:
            raise ImportError("websockets package required: pip install websockets")

        self.host = host
        self.port = port
        self.pool = pool
        self.writer = writer
        self.cert_file = cert_file
        self.key_file = key_file

        # Connected agents
        self._agents: Dict[str, ConnectedAgent] = {}
        self._websocket_to_agent: Dict[Any, str] = {}
        self._lock = threading.Lock()

        # Server state
        self._server = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

        # Callbacks
        self._on_agent_connect: Optional[Callable] = None
        self._on_agent_disconnect: Optional[Callable] = None
        self._on_agent_data: Optional[Callable] = None

    def set_callbacks(
        self,
        on_connect: Optional[Callable] = None,
        on_disconnect: Optional[Callable] = None,
        on_data: Optional[Callable] = None,
    ) -> None:
        """Set event callbacks."""
        self._on_agent_connect = on_connect
        self._on_agent_disconnect = on_disconnect
        self._on_agent_data = on_data

    def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for TLS."""
        if not self.cert_file or not self.key_file:
            return None

        cert_path = Path(self.cert_file).expanduser()
        key_path = Path(self.key_file).expanduser()

        if not cert_path.exists() or not key_path.exists():
            return None

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def _hash_token(self, token: str) -> str:
        """Hash a token for storage/comparison."""
        return hashlib.sha256(token.encode()).hexdigest()

    def _verify_agent(self, agent_id: str, token: str, hardware_id: str) -> bool:
        """Verify agent credentials against database."""
        if not self.pool:
            return False

        try:
            rows = self.pool.execute_read("""
                SELECT token_hash, hardware_id, status
                FROM relay_agents
                WHERE agent_id = ?
            """, (agent_id,))

            if not rows:
                return False

            row = rows[0]
            stored_hash = row["token_hash"]
            stored_hardware = row["hardware_id"]
            status = row["status"]

            # Check status
            if status == "revoked":
                return False

            # Verify hardware ID matches
            if stored_hardware != hardware_id:
                self._log_event(agent_id, "auth_fail", {
                    "reason": "hardware_mismatch",
                    "expected": stored_hardware,
                    "received": hardware_id,
                })
                return False

            # Verify token
            if self._hash_token(token) != stored_hash:
                self._log_event(agent_id, "auth_fail", {"reason": "invalid_token"})
                return False

            return True
        except Exception as e:
            print(f"Agent verification error: {e}")
            return False

    def _activate_agent(self, agent_id: str, ip_address: str, system_info: Dict) -> None:
        """Mark agent as active in database."""
        if not self.pool:
            return

        try:
            now = time.time()
            with self.pool.write_connection() as conn:
                conn.execute("""
                    UPDATE relay_agents SET
                        status = 'active',
                        last_seen = ?,
                        last_heartbeat = ?,
                        activated_at = COALESCE(activated_at, ?),
                        ip_address = ?,
                        hostname = ?,
                        os_type = ?,
                        os_version = ?,
                        python_version = ?,
                        agent_version = ?
                    WHERE agent_id = ?
                """, (
                    now, now, now, ip_address,
                    system_info.get("hostname"),
                    system_info.get("os_type"),
                    system_info.get("os_version"),
                    system_info.get("python_version"),
                    system_info.get("agent_version"),
                    agent_id,
                ))
                conn.commit()
        except Exception as e:
            print(f"Agent activation error: {e}")

    def _log_event(
        self,
        agent_id: str,
        event_type: str,
        event_data: Optional[Dict] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log an agent event to database."""
        if not self.pool:
            return

        try:
            with self.pool.write_connection() as conn:
                conn.execute("""
                    INSERT INTO relay_events (agent_id, event_type, event_data, ip_address, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    agent_id,
                    event_type,
                    json.dumps(event_data) if event_data else None,
                    ip_address,
                    time.time(),
                ))
                conn.commit()
        except Exception as e:
            print(f"Event logging error: {e}")

    def _store_metrics(self, agent_id: str, metric_type: str, data: Dict) -> None:
        """Store agent metrics in database."""
        if not self.pool:
            return

        try:
            with self.pool.write_connection() as conn:
                conn.execute("""
                    INSERT INTO relay_metrics (agent_id, metric_type, metric_data, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (agent_id, metric_type, json.dumps(data), time.time()))
                conn.commit()
        except Exception as e:
            print(f"Metrics storage error: {e}")

    def _store_flows(self, agent_id: str, flows: list) -> None:
        """Store agent flow data in database."""
        if not self.pool:
            return

        try:
            with self.pool.write_connection() as conn:
                for flow in flows:
                    conn.execute("""
                        INSERT INTO relay_flows (
                            agent_id, flow_key, src_ip, dst_ip, src_port, dst_port,
                            protocol, packets_sent, packets_recv, bytes_sent, bytes_recv,
                            first_seen, last_seen, dst_country, dst_hostname
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(agent_id, flow_key) DO UPDATE SET
                            packets_sent = packets_sent + excluded.packets_sent,
                            packets_recv = packets_recv + excluded.packets_recv,
                            bytes_sent = bytes_sent + excluded.bytes_sent,
                            bytes_recv = bytes_recv + excluded.bytes_recv,
                            last_seen = excluded.last_seen
                    """, (
                        agent_id,
                        flow.get("flow_key"),
                        flow.get("src_ip"),
                        flow.get("dst_ip"),
                        flow.get("src_port"),
                        flow.get("dst_port"),
                        flow.get("protocol"),
                        flow.get("packets_sent", 0),
                        flow.get("packets_recv", 0),
                        flow.get("bytes_sent", 0),
                        flow.get("bytes_recv", 0),
                        flow.get("first_seen"),
                        flow.get("last_seen"),
                        flow.get("dst_country"),
                        flow.get("dst_hostname"),
                    ))
                conn.commit()
        except Exception as e:
            print(f"Flow storage error: {e}")

    async def _handle_message(
        self,
        websocket: WebSocketServerProtocol,
        message: str,
    ) -> Optional[str]:
        """Handle incoming message from agent."""
        try:
            msg = RelayMessage.from_json(message)
        except json.JSONDecodeError:
            return RelayMessage.error("parse_error", "Invalid JSON").to_json()

        agent_id = self._websocket_to_agent.get(websocket)

        # Authentication required for most messages
        if msg.type == MessageType.AUTH_REQUEST.value:
            return await self._handle_auth(websocket, msg)

        # Check if authenticated
        if agent_id:
            agent = self._agents.get(agent_id)
            if not agent or not agent.authenticated:
                return RelayMessage.error("auth_required", "Authentication required").to_json()
        else:
            return RelayMessage.error("auth_required", "Authentication required").to_json()

        # Handle authenticated messages
        if msg.type == MessageType.HEARTBEAT.value:
            return await self._handle_heartbeat(agent_id, msg)
        elif msg.type == MessageType.METRICS.value:
            return await self._handle_metrics(agent_id, msg)
        elif msg.type == MessageType.FLOWS.value:
            return await self._handle_flows(agent_id, msg)
        elif msg.type == MessageType.DISCONNECT.value:
            return await self._handle_disconnect(agent_id, msg)

        return RelayMessage.error("unknown_type", f"Unknown message type: {msg.type}").to_json()

    async def _handle_auth(
        self,
        websocket: WebSocketServerProtocol,
        msg: RelayMessage,
    ) -> str:
        """Handle authentication request."""
        payload = msg.payload
        agent_id = payload.get("agent_id")
        token = payload.get("token")
        hardware_id = payload.get("hardware_id")
        system_info = payload.get("system_info", {})

        if not all([agent_id, token, hardware_id]):
            return RelayMessage.auth_response(
                success=False,
                message="Missing required fields",
            ).to_json()

        # Get client IP
        ip_address = websocket.remote_address[0] if websocket.remote_address else "unknown"

        # Verify credentials
        if not self._verify_agent(agent_id, token, hardware_id):
            self._log_event(agent_id, "auth_fail", {"ip": ip_address}, ip_address)
            return RelayMessage.auth_response(
                success=False,
                message="Authentication failed",
            ).to_json()

        # Generate session token
        session_token = secrets.token_hex(32)

        # Register agent
        with self._lock:
            agent = ConnectedAgent(
                agent_id=agent_id,
                hardware_id=hardware_id,
                websocket=websocket,
                ip_address=ip_address,
                session_token=session_token,
                system_info=system_info,
                authenticated=True,
            )
            self._agents[agent_id] = agent
            self._websocket_to_agent[websocket] = agent_id

        # Activate in database
        self._activate_agent(agent_id, ip_address, system_info)
        self._log_event(agent_id, "connect", system_info, ip_address)

        # Callback
        if self._on_agent_connect:
            self._on_agent_connect(agent_id, system_info)

        return RelayMessage.auth_response(
            success=True,
            message="Authenticated",
            session_token=session_token,
        ).to_json()

    async def _handle_heartbeat(self, agent_id: str, msg: RelayMessage) -> str:
        """Handle heartbeat message."""
        with self._lock:
            if agent_id in self._agents:
                self._agents[agent_id].last_heartbeat = time.time()

        # Update database
        if self.pool:
            try:
                with self.pool.write_connection() as conn:
                    conn.execute("""
                        UPDATE relay_agents
                        SET last_heartbeat = ?, last_seen = ?
                        WHERE agent_id = ?
                    """, (time.time(), time.time(), agent_id))
                    conn.commit()
            except Exception:
                pass

        return RelayMessage(
            type=MessageType.HEARTBEAT_ACK.value,
            payload={"server_time": time.time()},
        ).to_json()

    async def _handle_metrics(self, agent_id: str, msg: RelayMessage) -> str:
        """Handle metrics message."""
        payload = msg.payload
        metric_type = payload.get("metric_type")
        data = payload.get("data", {})

        self._store_metrics(agent_id, metric_type, data)

        if self._on_agent_data:
            self._on_agent_data(agent_id, "metrics", data)

        return RelayMessage(type=MessageType.ACK.value).to_json()

    async def _handle_flows(self, agent_id: str, msg: RelayMessage) -> str:
        """Handle flows data message."""
        payload = msg.payload
        flows = payload.get("flows", [])

        self._store_flows(agent_id, flows)

        if self._on_agent_data:
            self._on_agent_data(agent_id, "flows", flows)

        return RelayMessage(type=MessageType.ACK.value).to_json()

    async def _handle_disconnect(self, agent_id: str, msg: RelayMessage) -> str:
        """Handle graceful disconnect."""
        self._log_event(agent_id, "disconnect", {"reason": "client_request"})
        return RelayMessage(type=MessageType.ACK.value).to_json()

    async def _agent_handler(self, websocket: WebSocketServerProtocol) -> None:
        """Handle a single agent connection."""
        try:
            async for message in websocket:
                if len(message) > RelayProtocol.MAX_MESSAGE_SIZE:
                    await websocket.send(
                        RelayMessage.error("message_too_large", "Message exceeds size limit").to_json()
                    )
                    continue

                response = await self._handle_message(websocket, message)
                if response:
                    await websocket.send(response)

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            # Cleanup on disconnect
            agent_id = self._websocket_to_agent.pop(websocket, None)
            if agent_id:
                with self._lock:
                    agent = self._agents.pop(agent_id, None)

                if agent:
                    self._log_event(agent_id, "disconnect", {"reason": "connection_closed"}, agent.ip_address)

                    # Mark offline in database
                    if self.pool:
                        try:
                            with self.pool.write_connection() as conn:
                                conn.execute("""
                                    UPDATE relay_agents
                                    SET status = 'offline', last_seen = ?
                                    WHERE agent_id = ?
                                """, (time.time(), agent_id))
                                conn.commit()
                        except Exception:
                            pass

                    if self._on_agent_disconnect:
                        self._on_agent_disconnect(agent_id)

    async def _run_server(self) -> None:
        """Run the WebSocket server."""
        ssl_context = self._get_ssl_context()

        async with serve(
            self._agent_handler,
            self.host,
            self.port,
            ssl=ssl_context,
        ) as server:
            self._server = server
            self._running = True
            print(f"Relay server listening on {'wss' if ssl_context else 'ws'}://{self.host}:{self.port}")

            # Keep running until stopped
            while self._running:
                await asyncio.sleep(1)

    def start(self) -> None:
        """Start the relay server in a background thread."""
        if self._thread and self._thread.is_alive():
            return

        def run():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._run_server())

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the relay server."""
        self._running = False

        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)

        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def get_connected_agents(self) -> Dict[str, Dict]:
        """Get list of connected agents."""
        with self._lock:
            return {
                agent_id: {
                    "hardware_id": agent.hardware_id,
                    "ip_address": agent.ip_address,
                    "connected_at": agent.connected_at,
                    "last_heartbeat": agent.last_heartbeat,
                    "system_info": agent.system_info,
                }
                for agent_id, agent in self._agents.items()
            }

    def get_agent_count(self) -> int:
        """Get number of connected agents."""
        return len(self._agents)

    def register_agent(
        self,
        name: str,
        hardware_id: str,
    ) -> tuple[str, str]:
        """Register a new agent and return (agent_id, token).

        This is called from the control panel to create a new agent registration.
        """
        if not self.pool:
            raise RuntimeError("Database pool not configured")

        import uuid
        agent_id = str(uuid.uuid4())
        token = secrets.token_hex(32)
        token_hash = self._hash_token(token)

        with self.pool.write_connection() as conn:
            conn.execute("""
                INSERT INTO relay_agents (agent_id, name, hardware_id, token_hash, created_at, status)
                VALUES (?, ?, ?, ?, ?, 'pending')
            """, (agent_id, name, hardware_id, token_hash, time.time()))
            conn.commit()

        return agent_id, token

    def revoke_agent(self, agent_id: str) -> bool:
        """Revoke an agent's access."""
        if not self.pool:
            return False

        try:
            with self.pool.write_connection() as conn:
                conn.execute("""
                    UPDATE relay_agents
                    SET status = 'revoked', revoked_at = ?
                    WHERE agent_id = ?
                """, (time.time(), agent_id))
                conn.commit()

            # Disconnect if currently connected
            with self._lock:
                if agent_id in self._agents:
                    agent = self._agents[agent_id]
                    asyncio.run_coroutine_threadsafe(
                        agent.websocket.close(),
                        self._loop,
                    )
            return True
        except Exception:
            return False
