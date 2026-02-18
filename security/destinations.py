"""Alert destination handlers for sending alerts to external systems."""

import json
import logging
import socket
import time
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from queue import Queue, Empty
from typing import Optional, Dict, List, Any, TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from .alerts import Alert

logger = logging.getLogger(__name__)


class DestinationType(Enum):
    """Types of alert destinations."""
    WEBHOOK = "webhook"
    SYSLOG = "syslog"
    FILE = "file"
    EMAIL = "email"


@dataclass
class DestinationConfig:
    """Configuration for an alert destination."""
    type: DestinationType
    enabled: bool = True
    # Webhook config
    url: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    timeout: float = 10.0
    retry_count: int = 3
    retry_delay: float = 1.0
    # Syslog config
    host: Optional[str] = None
    port: int = 514
    protocol: str = "udp"  # udp or tcp
    facility: int = 1  # USER
    # File config
    path: Optional[str] = None
    max_size_mb: int = 100
    rotate_count: int = 5
    # Email config (placeholder for future)
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    recipients: Optional[List[str]] = None


class AlertDestination(ABC):
    """Abstract base class for alert destinations."""

    def __init__(self, config: DestinationConfig):
        self.config = config
        self._send_count = 0
        self._error_count = 0
        self._last_error: Optional[str] = None

    @abstractmethod
    def send(self, alert: "Alert") -> bool:
        """Send an alert to this destination.

        Args:
            alert: Alert to send

        Returns:
            True if send succeeded
        """
        pass

    def _format_alert(self, alert: "Alert") -> Dict[str, Any]:
        """Format alert as dictionary for sending."""
        return {
            "id": alert.id,
            "type": alert.alert_type.value if hasattr(alert.alert_type, 'value') else str(alert.alert_type),
            "severity": alert.severity.value if hasattr(alert.severity, 'value') else str(alert.severity),
            "title": alert.title,
            "description": alert.description,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "port": alert.port,
            "protocol": alert.protocol,
            "flow_key": alert.flow_key,
            "details": alert.details,
            "timestamp": alert.timestamp,
            "timestamp_iso": datetime.fromtimestamp(alert.timestamp).isoformat(),
            "acknowledged": alert.acknowledged,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get destination statistics."""
        return {
            "type": self.config.type.value,
            "enabled": self.config.enabled,
            "send_count": self._send_count,
            "error_count": self._error_count,
            "last_error": self._last_error,
        }


class WebhookDestination(AlertDestination):
    """Send alerts to a webhook URL."""

    def __init__(self, config: DestinationConfig):
        super().__init__(config)
        if not config.url:
            raise ValueError("Webhook destination requires URL")

    def send(self, alert: "Alert") -> bool:
        """Send alert to webhook."""
        if not self.config.enabled:
            return True

        payload = {
            "event": "packettracer_alert",
            "alert": self._format_alert(alert),
            "sent_at": datetime.now().isoformat(),
        }

        headers = {"Content-Type": "application/json"}
        if self.config.headers:
            headers.update(self.config.headers)

        for attempt in range(self.config.retry_count):
            try:
                response = requests.post(
                    self.config.url,
                    json=payload,
                    headers=headers,
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                self._send_count += 1
                logger.debug(f"Sent alert {alert.id} to webhook")
                return True

            except requests.RequestException as e:
                self._last_error = str(e)
                logger.warning(f"Webhook send attempt {attempt + 1} failed: {e}")
                if attempt < self.config.retry_count - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))

        self._error_count += 1
        logger.error(f"Failed to send alert {alert.id} to webhook after {self.config.retry_count} attempts")
        return False


class SyslogDestination(AlertDestination):
    """Send alerts to syslog server."""

    # Syslog severity mapping
    SEVERITY_MAP = {
        "CRITICAL": 2,  # Critical
        "HIGH": 3,      # Error
        "MEDIUM": 4,    # Warning
        "LOW": 5,       # Notice
        "INFO": 6,      # Informational
    }

    def __init__(self, config: DestinationConfig):
        super().__init__(config)
        if not config.host:
            raise ValueError("Syslog destination requires host")
        self._socket: Optional[socket.socket] = None

    def _get_socket(self) -> socket.socket:
        """Get or create syslog socket."""
        if self._socket is None:
            if self.config.protocol == "tcp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(self.config.timeout)
                self._socket.connect((self.config.host, self.config.port))
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._socket

    def _format_syslog_message(self, alert: "Alert") -> bytes:
        """Format alert as RFC 5424 syslog message."""
        # Get severity
        severity_name = alert.severity.name if hasattr(alert.severity, 'name') else str(alert.severity)
        severity = self.SEVERITY_MAP.get(severity_name, 6)

        # Calculate priority: facility * 8 + severity
        priority = self.config.facility * 8 + severity

        # RFC 5424 format
        timestamp = datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        hostname = socket.gethostname()
        app_name = "PacketTracer"
        proc_id = "-"
        msg_id = alert.alert_type.name if hasattr(alert.alert_type, 'name') else str(alert.alert_type)

        # Structured data
        sd = f'[alert@0 id="{alert.id}" src="{alert.source_ip}" dst="{alert.dest_ip}"]'

        # Message
        msg = f"{alert.title}: {alert.description}"

        # Build syslog message
        syslog_msg = f"<{priority}>1 {timestamp} {hostname} {app_name} {proc_id} {msg_id} {sd} {msg}"

        return syslog_msg.encode('utf-8')

    def send(self, alert: "Alert") -> bool:
        """Send alert to syslog."""
        if not self.config.enabled:
            return True

        try:
            sock = self._get_socket()
            message = self._format_syslog_message(alert)

            if self.config.protocol == "tcp":
                sock.sendall(message + b'\n')
            else:
                sock.sendto(message, (self.config.host, self.config.port))

            self._send_count += 1
            logger.debug(f"Sent alert {alert.id} to syslog")
            return True

        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            # Reset socket on error
            if self._socket:
                try:
                    self._socket.close()
                except:
                    pass
                self._socket = None
            logger.error(f"Failed to send alert {alert.id} to syslog: {e}")
            return False

    def close(self) -> None:
        """Close syslog socket."""
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None


class FileDestination(AlertDestination):
    """Write alerts to a file."""

    def __init__(self, config: DestinationConfig):
        super().__init__(config)
        if not config.path:
            raise ValueError("File destination requires path")
        self._lock = threading.Lock()
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Ensure output directory exists."""
        path = Path(self.config.path)
        path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max size."""
        path = Path(self.config.path)
        if not path.exists():
            return

        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb < self.config.max_size_mb:
            return

        # Rotate files
        for i in range(self.config.rotate_count - 1, 0, -1):
            old_path = Path(f"{self.config.path}.{i}")
            new_path = Path(f"{self.config.path}.{i + 1}")
            if old_path.exists():
                old_path.rename(new_path)

        # Rename current to .1
        path.rename(Path(f"{self.config.path}.1"))
        logger.info(f"Rotated alert log file: {self.config.path}")

    def send(self, alert: "Alert") -> bool:
        """Write alert to file."""
        if not self.config.enabled:
            return True

        try:
            with self._lock:
                self._rotate_if_needed()

                with open(self.config.path, 'a', encoding='utf-8') as f:
                    alert_data = self._format_alert(alert)
                    line = json.dumps(alert_data) + '\n'
                    f.write(line)

            self._send_count += 1
            logger.debug(f"Wrote alert {alert.id} to file")
            return True

        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            logger.error(f"Failed to write alert {alert.id} to file: {e}")
            return False


class AlertDispatcher:
    """Dispatch alerts to multiple destinations."""

    def __init__(self):
        self._destinations: List[AlertDestination] = []
        self._queue: Queue["Alert"] = Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def add_destination(self, destination: AlertDestination) -> None:
        """Add an alert destination."""
        self._destinations.append(destination)
        logger.info(f"Added alert destination: {destination.config.type.value}")

    def remove_destination(self, destination: AlertDestination) -> None:
        """Remove an alert destination."""
        if destination in self._destinations:
            self._destinations.remove(destination)

    def add_webhook(self, url: str, headers: Optional[Dict[str, str]] = None) -> WebhookDestination:
        """Add a webhook destination."""
        config = DestinationConfig(
            type=DestinationType.WEBHOOK,
            url=url,
            headers=headers,
        )
        dest = WebhookDestination(config)
        self.add_destination(dest)
        return dest

    def add_syslog(self, host: str, port: int = 514, protocol: str = "udp") -> SyslogDestination:
        """Add a syslog destination."""
        config = DestinationConfig(
            type=DestinationType.SYSLOG,
            host=host,
            port=port,
            protocol=protocol,
        )
        dest = SyslogDestination(config)
        self.add_destination(dest)
        return dest

    def add_file(self, path: str, max_size_mb: int = 100) -> FileDestination:
        """Add a file destination."""
        config = DestinationConfig(
            type=DestinationType.FILE,
            path=path,
            max_size_mb=max_size_mb,
        )
        dest = FileDestination(config)
        self.add_destination(dest)
        return dest

    def dispatch(self, alert: "Alert") -> None:
        """Queue an alert for dispatch."""
        self._queue.put(alert)

    def dispatch_sync(self, alert: "Alert") -> Dict[str, bool]:
        """Send alert to all destinations synchronously.

        Returns:
            Dict mapping destination type to success status
        """
        results = {}
        for dest in self._destinations:
            if dest.config.enabled:
                success = dest.send(alert)
                results[dest.config.type.value] = success
        return results

    def start(self) -> None:
        """Start background dispatch thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._dispatch_worker, daemon=True)
        self._thread.start()
        logger.info("Alert dispatcher started")

    def stop(self) -> None:
        """Stop background dispatch thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

        # Close any destinations that need cleanup
        for dest in self._destinations:
            if hasattr(dest, 'close'):
                dest.close()

        logger.info("Alert dispatcher stopped")

    def _dispatch_worker(self) -> None:
        """Background worker for dispatching alerts."""
        while self._running:
            try:
                alert = self._queue.get(timeout=1.0)
                self.dispatch_sync(alert)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error in alert dispatcher: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get dispatcher statistics."""
        return {
            "destinations": [d.get_stats() for d in self._destinations],
            "queue_size": self._queue.qsize(),
            "running": self._running,
        }
