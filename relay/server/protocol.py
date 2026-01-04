"""Relay communication protocol definitions."""

import json
import time
from enum import Enum, auto
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List

from config import (
    RELAY_AGENT_HEARTBEAT_INTERVAL,
    RELAY_MAX_MESSAGE_SIZE,
)


class MessageType(Enum):
    """Message types for relay protocol."""
    # Authentication
    AUTH_REQUEST = "auth_request"
    AUTH_RESPONSE = "auth_response"
    AUTH_CHALLENGE = "auth_challenge"

    # Connection management
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"
    DISCONNECT = "disconnect"

    # Data transfer
    METRICS = "metrics"
    FLOWS = "flows"
    DNS_QUERIES = "dns_queries"
    EVENTS = "events"

    # Commands (server -> agent)
    CMD_START_CAPTURE = "cmd_start_capture"
    CMD_STOP_CAPTURE = "cmd_stop_capture"
    CMD_UPDATE_CONFIG = "cmd_update_config"
    CMD_RESTART = "cmd_restart"
    CMD_STATUS = "cmd_status"

    # Responses
    CMD_RESPONSE = "cmd_response"
    ACK = "ack"
    ERROR = "error"


@dataclass
class RelayMessage:
    """Base message for relay protocol."""
    type: str
    timestamp: float = field(default_factory=time.time)
    message_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> "RelayMessage":
        """Deserialize from JSON string."""
        obj = json.loads(data)
        return cls(**obj)

    @classmethod
    def auth_request(
        cls,
        agent_id: str,
        token: str,
        hardware_id: str,
        system_info: Dict[str, str],
    ) -> "RelayMessage":
        """Create authentication request message."""
        return cls(
            type=MessageType.AUTH_REQUEST.value,
            payload={
                "agent_id": agent_id,
                "token": token,
                "hardware_id": hardware_id,
                "system_info": system_info,
            }
        )

    @classmethod
    def auth_response(
        cls,
        success: bool,
        message: str = "",
        session_token: Optional[str] = None,
    ) -> "RelayMessage":
        """Create authentication response message."""
        return cls(
            type=MessageType.AUTH_RESPONSE.value,
            payload={
                "success": success,
                "message": message,
                "session_token": session_token,
            }
        )

    @classmethod
    def heartbeat(cls, agent_id: str, status: Dict[str, Any]) -> "RelayMessage":
        """Create heartbeat message."""
        return cls(
            type=MessageType.HEARTBEAT.value,
            payload={
                "agent_id": agent_id,
                "status": status,
            }
        )

    @classmethod
    def metrics(
        cls,
        agent_id: str,
        metric_type: str,
        data: Dict[str, Any],
    ) -> "RelayMessage":
        """Create metrics message."""
        return cls(
            type=MessageType.METRICS.value,
            payload={
                "agent_id": agent_id,
                "metric_type": metric_type,
                "data": data,
            }
        )

    @classmethod
    def flows(cls, agent_id: str, flows: List[Dict[str, Any]]) -> "RelayMessage":
        """Create flows data message."""
        return cls(
            type=MessageType.FLOWS.value,
            payload={
                "agent_id": agent_id,
                "flows": flows,
            }
        )

    @classmethod
    def error(cls, code: str, message: str) -> "RelayMessage":
        """Create error message."""
        return cls(
            type=MessageType.ERROR.value,
            payload={
                "code": code,
                "message": message,
            }
        )


class RelayProtocol:
    """Protocol handler for relay messages."""

    PROTOCOL_VERSION = "1.0"
    HEARTBEAT_INTERVAL = RELAY_AGENT_HEARTBEAT_INTERVAL
    HEARTBEAT_TIMEOUT = RELAY_AGENT_HEARTBEAT_INTERVAL * 3
    MAX_MESSAGE_SIZE = RELAY_MAX_MESSAGE_SIZE

    @staticmethod
    def validate_message(msg: RelayMessage) -> bool:
        """Validate a relay message."""
        if not msg.type:
            return False
        try:
            MessageType(msg.type)
            return True
        except ValueError:
            return False

    @staticmethod
    def create_message_id() -> str:
        """Create a unique message ID."""
        import uuid
        return str(uuid.uuid4())[:8]
