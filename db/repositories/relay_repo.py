"""Repository for relay agent data."""

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from ..writer import DatabaseWriter, WriteOp


@dataclass
class AgentInfo:
    """Relay agent information."""
    id: int
    agent_id: str
    name: str
    hardware_id: str
    token_hash: str
    hostname: Optional[str]
    ip_address: Optional[str]
    os_type: Optional[str]
    os_version: Optional[str]
    python_version: Optional[str]
    agent_version: Optional[str]
    status: str
    last_seen: Optional[float]
    last_heartbeat: Optional[float]
    created_at: float
    activated_at: Optional[float]
    revoked_at: Optional[float]
    config: Dict[str, Any]

    @property
    def is_online(self) -> bool:
        """Check if agent is online (seen in last 90 seconds)."""
        if self.last_seen is None:
            return False
        return time.time() - self.last_seen < 90

    @property
    def host(self) -> str:
        """Get host display string (for compatibility)."""
        return self.ip_address or self.hostname or "unknown"

    @property
    def registered_at(self) -> float:
        """Alias for created_at (for compatibility)."""
        return self.created_at

    @property
    def system_info(self) -> Dict[str, Any]:
        """Get system info dict (for compatibility)."""
        return {
            "hostname": self.hostname,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "python_version": self.python_version,
            "agent_version": self.agent_version,
        }


@dataclass
class AgentEvent:
    """Agent event record."""
    id: int
    agent_id: str
    event_type: str
    timestamp: float
    event_data: Dict[str, Any]
    ip_address: Optional[str]

    @property
    def details(self) -> Dict[str, Any]:
        """Alias for event_data (for compatibility)."""
        return self.event_data


@dataclass
class AgentMetrics:
    """Agent system metrics."""
    id: int
    agent_id: str
    timestamp: float
    metric_type: str
    metric_data: Dict[str, Any]

    @property
    def cpu_percent(self) -> float:
        """Get CPU percent from metric data."""
        if self.metric_type == "system":
            cpu = self.metric_data.get("cpu", {})
            return cpu.get("percent", 0.0)
        return 0.0

    @property
    def memory_percent(self) -> float:
        """Get memory percent from metric data."""
        if self.metric_type == "system":
            mem = self.metric_data.get("memory", {})
            return mem.get("percent", 0.0)
        return 0.0

    @property
    def disk_percent(self) -> float:
        """Get disk percent from metric data."""
        if self.metric_type == "system":
            disk = self.metric_data.get("disk", {})
            return disk.get("percent", 0.0)
        return 0.0

    @property
    def network_rx_bytes(self) -> int:
        """Get network RX bytes from metric data."""
        if self.metric_type == "system":
            network = self.metric_data.get("network", {})
            return sum(iface.get("rx_bytes", 0) for iface in network.values())
        return 0

    @property
    def network_tx_bytes(self) -> int:
        """Get network TX bytes from metric data."""
        if self.metric_type == "system":
            network = self.metric_data.get("network", {})
            return sum(iface.get("tx_bytes", 0) for iface in network.values())
        return 0


class RelayRepository:
    """Repository for relay agent data."""

    def __init__(self, connection_pool, writer: Optional[DatabaseWriter] = None):
        """Initialize repository.

        Args:
            connection_pool: Database connection pool
            writer: Optional database writer for async operations
        """
        self._pool = connection_pool
        self._writer = writer

    @staticmethod
    def hash_token(token: str) -> str:
        """Hash a token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def generate_token() -> str:
        """Generate a new authentication token."""
        return secrets.token_urlsafe(32)

    def register_agent(
        self,
        agent_id: str,
        name: str,
        host: str,
        hardware_id: str,
        token: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, str]:
        """Register a new agent.

        Args:
            agent_id: Unique agent identifier
            name: Human-readable name
            host: Host address (IP or hostname)
            hardware_id: Hardware fingerprint
            token: Auth token (generated if not provided)
            config: Agent configuration

        Returns:
            Tuple of (agent_id, token)
        """
        if token is None:
            token = self.generate_token()

        token_hash = self.hash_token(token)
        now = time.time()

        with self._pool.write_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO relay_agents (
                    agent_id, name, hardware_id, token_hash,
                    ip_address, status, last_seen, created_at, config
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    name = excluded.name,
                    token_hash = excluded.token_hash,
                    config = excluded.config
            """, (
                agent_id, name, hardware_id, token_hash,
                host, now, now,
                json.dumps(config) if config else "{}"
            ))
            conn.commit()

        return agent_id, token

    def verify_token(self, agent_id: str, token: str) -> bool:
        """Verify agent authentication token.

        Args:
            agent_id: Agent identifier
            token: Token to verify

        Returns:
            True if token is valid
        """
        token_hash = self.hash_token(token)
        row = self._pool.execute_read_one(
            "SELECT token_hash FROM relay_agents WHERE agent_id = ?",
            (agent_id,)
        )
        if row is None:
            return False
        return row["token_hash"] == token_hash

    def verify_hardware_id(self, agent_id: str, hardware_id: str) -> bool:
        """Verify agent hardware ID matches registered value.

        Args:
            agent_id: Agent identifier
            hardware_id: Hardware ID to verify

        Returns:
            True if hardware ID matches
        """
        row = self._pool.execute_read_one(
            "SELECT hardware_id FROM relay_agents WHERE agent_id = ?",
            (agent_id,)
        )
        if row is None:
            return False
        return row["hardware_id"] == hardware_id

    def _row_to_agent_info(self, row) -> AgentInfo:
        """Convert a database row to AgentInfo."""
        config_str = row["config"]
        config = json.loads(config_str) if config_str else {}

        return AgentInfo(
            id=row["id"],
            agent_id=row["agent_id"],
            name=row["name"],
            hardware_id=row["hardware_id"],
            token_hash=row["token_hash"],
            hostname=row["hostname"],
            ip_address=row["ip_address"],
            os_type=row["os_type"],
            os_version=row["os_version"],
            python_version=row["python_version"],
            agent_version=row["agent_version"],
            status=row["status"],
            last_seen=row["last_seen"],
            last_heartbeat=row["last_heartbeat"],
            created_at=row["created_at"],
            activated_at=row["activated_at"],
            revoked_at=row["revoked_at"],
            config=config,
        )

    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        """Get agent by ID.

        Args:
            agent_id: Agent identifier

        Returns:
            AgentInfo or None if not found
        """
        row = self._pool.execute_read_one("""
            SELECT id, agent_id, name, hardware_id, token_hash,
                   hostname, ip_address, os_type, os_version,
                   python_version, agent_version, status,
                   last_seen, last_heartbeat, created_at,
                   activated_at, revoked_at, config
            FROM relay_agents
            WHERE agent_id = ?
        """, (agent_id,))

        if row is None:
            return None

        return self._row_to_agent_info(row)

    def get_all_agents(self, include_revoked: bool = False) -> List[AgentInfo]:
        """Get all registered agents.

        Args:
            include_revoked: Include revoked agents

        Returns:
            List of AgentInfo
        """
        if include_revoked:
            rows = self._pool.execute_read("""
                SELECT id, agent_id, name, hardware_id, token_hash,
                       hostname, ip_address, os_type, os_version,
                       python_version, agent_version, status,
                       last_seen, last_heartbeat, created_at,
                       activated_at, revoked_at, config
                FROM relay_agents
                ORDER BY last_seen DESC
            """)
        else:
            rows = self._pool.execute_read("""
                SELECT id, agent_id, name, hardware_id, token_hash,
                       hostname, ip_address, os_type, os_version,
                       python_version, agent_version, status,
                       last_seen, last_heartbeat, created_at,
                       activated_at, revoked_at, config
                FROM relay_agents
                WHERE status != 'revoked'
                ORDER BY last_seen DESC
            """)

        return [self._row_to_agent_info(row) for row in rows]

    def get_online_agents(self) -> List[AgentInfo]:
        """Get agents that are currently online.

        Returns:
            List of online AgentInfo
        """
        cutoff = time.time() - 90  # 90 second timeout
        rows = self._pool.execute_read("""
            SELECT id, agent_id, name, hardware_id, token_hash,
                   hostname, ip_address, os_type, os_version,
                   python_version, agent_version, status,
                   last_seen, last_heartbeat, created_at,
                   activated_at, revoked_at, config
            FROM relay_agents
            WHERE status = 'active' AND last_seen > ?
            ORDER BY last_seen DESC
        """, (cutoff,))

        return [self._row_to_agent_info(row) for row in rows]

    def update_agent_status(
        self,
        agent_id: str,
        status: str,
        system_info: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Update agent status.

        Args:
            agent_id: Agent identifier
            status: New status (active, offline, error, revoked)
            system_info: Optional system info update
            ip_address: Optional IP address update
        """
        now = time.time()

        if self._writer:
            self._writer.queue_write(
                WriteOp.UPDATE_AGENT_STATUS,
                {
                    "agent_id": agent_id,
                    "status": status,
                    "last_seen": now,
                    "system_info": system_info,
                    "ip_address": ip_address,
                }
            )
        else:
            with self._pool.write_connection() as conn:
                if system_info:
                    conn.execute("""
                        UPDATE relay_agents
                        SET status = ?, last_seen = ?,
                            hostname = COALESCE(?, hostname),
                            ip_address = COALESCE(?, ip_address),
                            os_type = COALESCE(?, os_type),
                            os_version = COALESCE(?, os_version),
                            python_version = COALESCE(?, python_version),
                            agent_version = COALESCE(?, agent_version)
                        WHERE agent_id = ?
                    """, (
                        status, now,
                        system_info.get("hostname"),
                        ip_address,
                        system_info.get("os_type"),
                        system_info.get("os_version"),
                        system_info.get("python_version"),
                        system_info.get("agent_version"),
                        agent_id,
                    ))
                else:
                    conn.execute("""
                        UPDATE relay_agents
                        SET status = ?, last_seen = ?,
                            ip_address = COALESCE(?, ip_address)
                        WHERE agent_id = ?
                    """, (status, now, ip_address, agent_id))
                conn.commit()

    def update_heartbeat(self, agent_id: str, ip_address: Optional[str] = None) -> None:
        """Update agent heartbeat timestamp.

        Args:
            agent_id: Agent identifier
            ip_address: Optional IP address update
        """
        now = time.time()
        if self._writer:
            self._writer.queue_write(
                WriteOp.UPDATE_AGENT_HEARTBEAT,
                {"agent_id": agent_id, "last_seen": now, "ip_address": ip_address}
            )
        else:
            with self._pool.write_connection() as conn:
                conn.execute("""
                    UPDATE relay_agents
                    SET last_seen = ?, last_heartbeat = ?, status = 'active',
                        ip_address = COALESCE(?, ip_address)
                    WHERE agent_id = ?
                """, (now, now, ip_address, agent_id))
                conn.commit()

    def revoke_agent(self, agent_id: str) -> bool:
        """Revoke agent access.

        Args:
            agent_id: Agent identifier

        Returns:
            True if agent was revoked
        """
        now = time.time()
        with self._pool.write_connection() as conn:
            cursor = conn.execute("""
                UPDATE relay_agents
                SET status = 'revoked', token_hash = '', revoked_at = ?
                WHERE agent_id = ?
            """, (now, agent_id))
            conn.commit()
            return cursor.rowcount > 0

    def delete_agent(self, agent_id: str) -> bool:
        """Delete agent and all associated data.

        Args:
            agent_id: Agent identifier

        Returns:
            True if agent was deleted
        """
        with self._pool.write_connection() as conn:
            # Delete associated data first (foreign keys should handle this with CASCADE)
            conn.execute("DELETE FROM relay_events WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM relay_metrics WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM relay_flows WHERE agent_id = ?", (agent_id,))
            # Delete agent
            cursor = conn.execute("DELETE FROM relay_agents WHERE agent_id = ?", (agent_id,))
            conn.commit()
            return cursor.rowcount > 0

    def log_event(
        self,
        agent_id: str,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log an agent event.

        Args:
            agent_id: Agent identifier
            event_type: Event type (connect, disconnect, error, etc.)
            details: Event details
            ip_address: IP address of agent
        """
        now = time.time()

        if self._writer:
            self._writer.queue_write(
                WriteOp.INSERT_RELAY_EVENT,
                {
                    "agent_id": agent_id,
                    "event_type": event_type,
                    "timestamp": now,
                    "event_data": json.dumps(details or {}),
                    "ip_address": ip_address,
                }
            )
        else:
            with self._pool.write_connection() as conn:
                conn.execute("""
                    INSERT INTO relay_events (agent_id, event_type, timestamp, event_data, ip_address)
                    VALUES (?, ?, ?, ?, ?)
                """, (agent_id, event_type, now, json.dumps(details or {}), ip_address))
                conn.commit()

    def get_events(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        since: Optional[float] = None,
    ) -> List[AgentEvent]:
        """Get agent events.

        Args:
            agent_id: Filter by agent ID
            event_type: Filter by event type
            limit: Maximum events to return
            since: Only events after this timestamp

        Returns:
            List of AgentEvent
        """
        query = "SELECT id, agent_id, event_type, timestamp, event_data, ip_address FROM relay_events WHERE 1=1"
        params: list = []

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if since:
            query += " AND timestamp > ?"
            params.append(since)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._pool.execute_read(query, tuple(params))

        events = []
        for row in rows:
            event_data_str = row["event_data"]
            event_data = json.loads(event_data_str) if event_data_str else {}
            events.append(AgentEvent(
                id=row["id"],
                agent_id=row["agent_id"],
                event_type=row["event_type"],
                timestamp=row["timestamp"],
                event_data=event_data,
                ip_address=row["ip_address"],
            ))
        return events

    def store_metrics(
        self,
        agent_id: str,
        metrics: Dict[str, Any],
        metric_type: str = "system",
    ) -> None:
        """Store agent system metrics.

        Args:
            agent_id: Agent identifier
            metrics: Metrics data (cpu, memory, disk, network)
            metric_type: Type of metrics
        """
        now = time.time()
        metric_data = json.dumps(metrics)

        if self._writer:
            self._writer.queue_write(
                WriteOp.INSERT_RELAY_METRICS,
                {
                    "agent_id": agent_id,
                    "timestamp": now,
                    "metric_type": metric_type,
                    "metric_data": metric_data,
                }
            )
        else:
            with self._pool.write_connection() as conn:
                conn.execute("""
                    INSERT INTO relay_metrics (agent_id, timestamp, metric_type, metric_data)
                    VALUES (?, ?, ?, ?)
                """, (agent_id, now, metric_type, metric_data))
                conn.commit()

    def get_metrics(
        self,
        agent_id: str,
        limit: int = 100,
        since: Optional[float] = None,
        metric_type: Optional[str] = None,
    ) -> List[AgentMetrics]:
        """Get agent metrics.

        Args:
            agent_id: Agent identifier
            limit: Maximum records to return
            since: Only metrics after this timestamp
            metric_type: Filter by metric type

        Returns:
            List of AgentMetrics
        """
        query = """
            SELECT id, agent_id, timestamp, metric_type, metric_data
            FROM relay_metrics
            WHERE agent_id = ?
        """
        params: list = [agent_id]

        if since:
            query += " AND timestamp > ?"
            params.append(since)
        if metric_type:
            query += " AND metric_type = ?"
            params.append(metric_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._pool.execute_read(query, tuple(params))

        metrics = []
        for row in rows:
            metric_data_str = row["metric_data"]
            metric_data = json.loads(metric_data_str) if metric_data_str else {}
            metrics.append(AgentMetrics(
                id=row["id"],
                agent_id=row["agent_id"],
                timestamp=row["timestamp"],
                metric_type=row["metric_type"],
                metric_data=metric_data,
            ))
        return metrics

    def get_agent_summary(self, agent_id: str) -> Dict[str, Any]:
        """Get summary statistics for an agent.

        Args:
            agent_id: Agent identifier

        Returns:
            Summary with event counts, latest metrics, etc.
        """
        # Get event counts
        rows = self._pool.execute_read("""
            SELECT event_type, COUNT(*) as count
            FROM relay_events
            WHERE agent_id = ?
            GROUP BY event_type
        """, (agent_id,))
        event_counts = {row["event_type"]: row["count"] for row in rows}

        # Get latest metrics
        row = self._pool.execute_read_one("""
            SELECT metric_type, metric_data, timestamp
            FROM relay_metrics
            WHERE agent_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (agent_id,))

        latest_metrics = None
        if row:
            metric_data = json.loads(row["metric_data"]) if row["metric_data"] else {}
            latest_metrics = {
                "metric_type": row["metric_type"],
                "data": metric_data,
                "timestamp": row["timestamp"],
            }

        # Get flow count
        row = self._pool.execute_read_one("""
            SELECT COUNT(*) as count FROM relay_flows WHERE agent_id = ?
        """, (agent_id,))
        flow_count = row["count"] if row else 0

        return {
            "agent_id": agent_id,
            "event_counts": event_counts,
            "latest_metrics": latest_metrics,
            "flow_count": flow_count,
        }

    def cleanup_old_data(self, max_age_days: int = 30) -> Dict[str, int]:
        """Clean up old data from relay tables.

        Args:
            max_age_days: Delete data older than this

        Returns:
            Dictionary with counts of deleted records
        """
        cutoff = time.time() - (max_age_days * 86400)

        with self._pool.write_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM relay_events WHERE timestamp < ?",
                (cutoff,)
            )
            events_deleted = cursor.rowcount

            cursor = conn.execute(
                "DELETE FROM relay_metrics WHERE timestamp < ?",
                (cutoff,)
            )
            metrics_deleted = cursor.rowcount

            cursor = conn.execute(
                "DELETE FROM relay_flows WHERE first_seen < ?",
                (cutoff,)
            )
            flows_deleted = cursor.rowcount

            conn.commit()

        return {
            "events_deleted": events_deleted,
            "metrics_deleted": metrics_deleted,
            "flows_deleted": flows_deleted,
        }
