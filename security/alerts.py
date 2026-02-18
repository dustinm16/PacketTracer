"""Alerting engine with configurable rules and triggers."""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Callable, Any, Set
from enum import Enum
from collections import deque

from tracking.flow import Flow
from tracking.ports import ScanActivity


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class AlertType(Enum):
    """Types of alerts."""
    PORT_SCAN = "port_scan"
    HIGH_BANDWIDTH = "high_bandwidth"
    NEW_HOST = "new_host"
    MALICIOUS_IP = "malicious_ip"
    SUSPICIOUS_PORT = "suspicious_port"
    CONNECTION_SPIKE = "connection_spike"
    DNS_ANOMALY = "dns_anomaly"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    BLACKLISTED_IP = "blacklisted_ip"
    GEOLOCATION = "geolocation"
    CUSTOM = "custom"


@dataclass
class Alert:
    """Represents a security alert."""
    id: str
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    flow_key: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    acknowledged: bool = False
    acknowledged_at: Optional[float] = None
    acknowledged_by: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert alert to dictionary."""
        return {
            "id": self.id,
            "type": self.alert_type.value,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "port": self.port,
            "protocol": self.protocol,
            "flow_key": self.flow_key,
            "details": self.details,
            "timestamp": self.timestamp,
            "acknowledged": self.acknowledged,
        }


@dataclass
class AlertRule:
    """Configurable alert rule."""
    name: str
    alert_type: AlertType
    enabled: bool = True
    severity: AlertSeverity = AlertSeverity.MEDIUM
    # Thresholds
    threshold: float = 0
    time_window: float = 60  # seconds
    cooldown: float = 300  # seconds between repeated alerts
    # Filters
    include_ips: List[str] = field(default_factory=list)
    exclude_ips: List[str] = field(default_factory=list)
    include_ports: List[int] = field(default_factory=list)
    exclude_ports: List[int] = field(default_factory=list)
    # Custom condition (Python expression)
    condition: Optional[str] = None

    def matches_ip(self, ip: str) -> bool:
        """Check if IP matches rule filters."""
        if self.exclude_ips and ip in self.exclude_ips:
            return False
        if self.include_ips and ip not in self.include_ips:
            return False
        return True

    def matches_port(self, port: int) -> bool:
        """Check if port matches rule filters."""
        if self.exclude_ports and port in self.exclude_ports:
            return False
        if self.include_ports and port not in self.include_ports:
            return False
        return True


# Default suspicious ports (common attack vectors)
SUSPICIOUS_PORTS = {
    23: "Telnet",
    135: "MS-RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    3389: "RDP",
    4444: "Metasploit",
    5900: "VNC",
    6666: "IRC (backdoor)",
    6667: "IRC",
    31337: "Back Orifice",
}

# Countries often associated with attacks (for geo-alerts)
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR"}


class AlertEngine:
    """Engine for detecting and generating security alerts."""

    def __init__(
        self,
        max_alerts: int = 1000,
        callback: Optional[Callable[[Alert], None]] = None,
    ):
        self.max_alerts = max_alerts
        self.callback = callback

        # Alert storage
        self._alerts: deque[Alert] = deque(maxlen=max_alerts)
        self._alerts_lock = threading.Lock()

        # Rules
        self._rules: Dict[str, AlertRule] = {}
        self._rules_lock = threading.Lock()

        # Cooldown tracking: rule_name -> {key: last_alert_time}
        self._cooldowns: Dict[str, Dict[str, float]] = {}

        # State tracking
        self._known_hosts: Set[str] = set()
        self._connection_counts: deque = deque(maxlen=60)  # Last 60 seconds
        self._last_second = 0

        # Blacklists
        self._ip_blacklist: Set[str] = set()
        self._domain_blacklist: Set[str] = set()

        # Statistics
        self.alerts_generated = 0
        self.alerts_suppressed = 0

        # Initialize default rules
        self._init_default_rules()

        # Alert ID counter
        self._alert_counter = 0
        self._counter_lock = threading.Lock()

    def _init_default_rules(self) -> None:
        """Initialize default alert rules."""
        default_rules = [
            AlertRule(
                name="port_scan_detection",
                alert_type=AlertType.PORT_SCAN,
                severity=AlertSeverity.HIGH,
                threshold=10,  # More than 10 unique ports
                time_window=60,
                cooldown=300,
            ),
            AlertRule(
                name="high_bandwidth",
                alert_type=AlertType.HIGH_BANDWIDTH,
                severity=AlertSeverity.MEDIUM,
                threshold=100_000_000,  # 100 MB in time window
                time_window=60,
                cooldown=300,
            ),
            AlertRule(
                name="new_external_host",
                alert_type=AlertType.NEW_HOST,
                severity=AlertSeverity.INFO,
                cooldown=3600,  # Once per hour per host
            ),
            AlertRule(
                name="suspicious_port_access",
                alert_type=AlertType.SUSPICIOUS_PORT,
                severity=AlertSeverity.MEDIUM,
                cooldown=300,
            ),
            AlertRule(
                name="connection_spike",
                alert_type=AlertType.CONNECTION_SPIKE,
                severity=AlertSeverity.MEDIUM,
                threshold=100,  # 100+ new connections per second
                time_window=10,
                cooldown=60,
            ),
            AlertRule(
                name="blacklisted_ip",
                alert_type=AlertType.BLACKLISTED_IP,
                severity=AlertSeverity.CRITICAL,
                cooldown=300,
            ),
            AlertRule(
                name="high_risk_country",
                alert_type=AlertType.GEOLOCATION,
                severity=AlertSeverity.LOW,
                cooldown=600,
            ),
        ]

        for rule in default_rules:
            self._rules[rule.name] = rule

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        with self._counter_lock:
            self._alert_counter += 1
            return f"ALT-{int(time.time())}-{self._alert_counter:06d}"

    def add_rule(self, rule: AlertRule) -> None:
        """Add or update an alert rule."""
        with self._rules_lock:
            self._rules[rule.name] = rule

    def remove_rule(self, name: str) -> bool:
        """Remove an alert rule."""
        with self._rules_lock:
            if name in self._rules:
                del self._rules[name]
                return True
        return False

    def get_rules(self) -> List[AlertRule]:
        """Get all alert rules."""
        with self._rules_lock:
            return list(self._rules.values())

    def enable_rule(self, name: str, enabled: bool = True) -> bool:
        """Enable or disable a rule."""
        with self._rules_lock:
            if name in self._rules:
                self._rules[name].enabled = enabled
                return True
        return False

    def add_to_blacklist(self, ip: str) -> None:
        """Add IP to blacklist."""
        self._ip_blacklist.add(ip)

    def remove_from_blacklist(self, ip: str) -> None:
        """Remove IP from blacklist."""
        self._ip_blacklist.discard(ip)

    def is_blacklisted(self, ip: str) -> bool:
        """Check if IP is blacklisted."""
        return ip in self._ip_blacklist

    def _check_cooldown(self, rule_name: str, key: str) -> bool:
        """Check if alert is in cooldown period."""
        rule = self._rules.get(rule_name)
        if not rule:
            return False

        if rule_name not in self._cooldowns:
            self._cooldowns[rule_name] = {}

        cooldowns = self._cooldowns[rule_name]
        now = time.time()

        if key in cooldowns:
            if now - cooldowns[key] < rule.cooldown:
                return True  # Still in cooldown

        cooldowns[key] = now
        return False

    def _create_alert(
        self,
        rule: AlertRule,
        title: str,
        description: str,
        **kwargs
    ) -> Alert:
        """Create and store an alert."""
        alert = Alert(
            id=self._generate_alert_id(),
            alert_type=rule.alert_type,
            severity=rule.severity,
            title=title,
            description=description,
            **kwargs
        )

        with self._alerts_lock:
            self._alerts.append(alert)

        self.alerts_generated += 1

        if self.callback:
            self.callback(alert)

        return alert

    # =========================================================================
    # Detection Methods
    # =========================================================================

    def check_flow(self, flow: Flow) -> List[Alert]:
        """Check a flow for alert conditions."""
        alerts = []

        # Check blacklist
        alert = self._check_blacklist(flow)
        if alert:
            alerts.append(alert)

        # Check suspicious ports
        alert = self._check_suspicious_port(flow)
        if alert:
            alerts.append(alert)

        # Check new host
        alert = self._check_new_host(flow)
        if alert:
            alerts.append(alert)

        # Check high bandwidth
        alert = self._check_high_bandwidth(flow)
        if alert:
            alerts.append(alert)

        return alerts

    def check_scan_activity(self, activity: ScanActivity) -> Optional[Alert]:
        """Check for port scan alerts."""
        rule = self._rules.get("port_scan_detection")
        if not rule or not rule.enabled:
            return None

        if activity.unique_ports < rule.threshold:
            return None

        if not rule.matches_ip(activity.src_ip):
            return None

        cooldown_key = activity.src_ip
        if self._check_cooldown("port_scan_detection", cooldown_key):
            self.alerts_suppressed += 1
            return None

        return self._create_alert(
            rule=rule,
            title=f"Port Scan Detected from {activity.src_ip}",
            description=f"Source IP {activity.src_ip} scanned {activity.unique_ports} ports "
                       f"at {activity.scan_rate:.1f} ports/sec",
            source_ip=activity.src_ip,
            details={
                "unique_ports": activity.unique_ports,
                "scan_rate": activity.scan_rate,
                "packet_count": activity.packet_count,
                "ports_sample": list(activity.ports_hit)[:20],
            }
        )

    def check_reputation(self, ip: str, reputation_result) -> Optional[Alert]:
        """Check reputation result for alerts."""
        if not reputation_result.is_malicious:
            return None

        rule = self._rules.get("blacklisted_ip")
        if not rule or not rule.enabled:
            # Fall back to creating alert anyway for malicious IPs
            rule = AlertRule(
                name="malicious_ip",
                alert_type=AlertType.MALICIOUS_IP,
                severity=AlertSeverity.HIGH,
            )

        cooldown_key = ip
        if self._check_cooldown("blacklisted_ip", cooldown_key):
            self.alerts_suppressed += 1
            return None

        return self._create_alert(
            rule=rule,
            title=f"Malicious IP Detected: {ip}",
            description=f"IP {ip} has threat level {reputation_result.threat_level.name} "
                       f"with {reputation_result.total_reports} reports",
            source_ip=ip,
            details={
                "threat_level": reputation_result.threat_level.name,
                "confidence_score": reputation_result.confidence_score,
                "total_reports": reputation_result.total_reports,
                "categories": reputation_result.categories,
                "is_tor": reputation_result.is_tor,
                "is_vpn": reputation_result.is_vpn,
                "is_proxy": reputation_result.is_proxy,
                "country_code": reputation_result.country_code,
            }
        )

    def check_geolocation(self, ip: str, country_code: str) -> Optional[Alert]:
        """Check for high-risk country alerts."""
        if country_code not in HIGH_RISK_COUNTRIES:
            return None

        rule = self._rules.get("high_risk_country")
        if not rule or not rule.enabled:
            return None

        cooldown_key = f"{ip}_{country_code}"
        if self._check_cooldown("high_risk_country", cooldown_key):
            self.alerts_suppressed += 1
            return None

        return self._create_alert(
            rule=rule,
            title=f"Connection from High-Risk Country: {country_code}",
            description=f"Traffic detected from {ip} located in {country_code}",
            source_ip=ip,
            details={"country_code": country_code}
        )

    def _check_blacklist(self, flow: Flow) -> Optional[Alert]:
        """Check if flow involves blacklisted IP."""
        blacklisted_ip = None
        if flow.src_ip in self._ip_blacklist:
            blacklisted_ip = flow.src_ip
        elif flow.dst_ip in self._ip_blacklist:
            blacklisted_ip = flow.dst_ip

        if not blacklisted_ip:
            return None

        rule = self._rules.get("blacklisted_ip")
        if not rule or not rule.enabled:
            return None

        cooldown_key = blacklisted_ip
        if self._check_cooldown("blacklisted_ip", cooldown_key):
            self.alerts_suppressed += 1
            return None

        return self._create_alert(
            rule=rule,
            title=f"Blacklisted IP Communication: {blacklisted_ip}",
            description=f"Traffic detected to/from blacklisted IP {blacklisted_ip}",
            source_ip=flow.src_ip,
            dest_ip=flow.dst_ip,
            flow_key=flow.flow_key,
        )

    def _check_suspicious_port(self, flow: Flow) -> Optional[Alert]:
        """Check for suspicious port access."""
        port = None
        port_name = None

        if flow.dst_port in SUSPICIOUS_PORTS:
            port = flow.dst_port
            port_name = SUSPICIOUS_PORTS[port]
        elif flow.src_port in SUSPICIOUS_PORTS:
            port = flow.src_port
            port_name = SUSPICIOUS_PORTS[port]

        if not port:
            return None

        rule = self._rules.get("suspicious_port_access")
        if not rule or not rule.enabled:
            return None

        if not rule.matches_port(port):
            return None

        cooldown_key = f"{flow.src_ip}_{port}"
        if self._check_cooldown("suspicious_port_access", cooldown_key):
            self.alerts_suppressed += 1
            return None

        return self._create_alert(
            rule=rule,
            title=f"Suspicious Port Access: {port} ({port_name})",
            description=f"{flow.src_ip} -> {flow.dst_ip}:{port} ({port_name})",
            source_ip=flow.src_ip,
            dest_ip=flow.dst_ip,
            port=port,
            protocol=flow.protocol_name,
            flow_key=flow.flow_key,
            details={"service": port_name}
        )

    def _check_new_host(self, flow: Flow) -> Optional[Alert]:
        """Check for new external host."""
        from utils.network import is_private_ip

        # Only alert on new external hosts
        new_host = None
        if not is_private_ip(flow.dst_ip) and flow.dst_ip not in self._known_hosts:
            new_host = flow.dst_ip
            self._known_hosts.add(flow.dst_ip)
        elif not is_private_ip(flow.src_ip) and flow.src_ip not in self._known_hosts:
            new_host = flow.src_ip
            self._known_hosts.add(flow.src_ip)

        if not new_host:
            return None

        rule = self._rules.get("new_external_host")
        if not rule or not rule.enabled:
            return None

        cooldown_key = new_host
        if self._check_cooldown("new_external_host", cooldown_key):
            self.alerts_suppressed += 1
            return None

        return self._create_alert(
            rule=rule,
            title=f"New External Host: {new_host}",
            description=f"First communication with external IP {new_host}",
            source_ip=flow.src_ip if new_host == flow.dst_ip else new_host,
            dest_ip=flow.dst_ip if new_host == flow.dst_ip else flow.src_ip,
        )

    def _check_high_bandwidth(self, flow: Flow) -> Optional[Alert]:
        """Check for high bandwidth usage."""
        rule = self._rules.get("high_bandwidth")
        if not rule or not rule.enabled:
            return None

        if flow.total_bytes < rule.threshold:
            return None

        cooldown_key = flow.flow_key
        if self._check_cooldown("high_bandwidth", cooldown_key):
            self.alerts_suppressed += 1
            return None

        return self._create_alert(
            rule=rule,
            title=f"High Bandwidth Flow: {flow.total_bytes / 1_000_000:.1f} MB",
            description=f"{flow.src_ip} -> {flow.dst_ip} transferred {flow.total_bytes / 1_000_000:.1f} MB",
            source_ip=flow.src_ip,
            dest_ip=flow.dst_ip,
            flow_key=flow.flow_key,
            details={
                "bytes_sent": flow.bytes_sent,
                "bytes_recv": flow.bytes_recv,
                "total_bytes": flow.total_bytes,
                "duration": flow.duration,
            }
        )

    # =========================================================================
    # Alert Management
    # =========================================================================

    def get_alerts(
        self,
        limit: int = 100,
        severity: Optional[AlertSeverity] = None,
        alert_type: Optional[AlertType] = None,
        unacknowledged_only: bool = False,
    ) -> List[Alert]:
        """Get alerts with optional filtering."""
        with self._alerts_lock:
            alerts = list(self._alerts)

        # Apply filters
        if severity:
            alerts = [a for a in alerts if a.severity.value >= severity.value]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]

        # Sort by timestamp descending and limit
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return alerts[:limit]

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get a specific alert by ID."""
        with self._alerts_lock:
            for alert in self._alerts:
                if alert.id == alert_id:
                    return alert
        return None

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = "user") -> bool:
        """Acknowledge an alert."""
        with self._alerts_lock:
            for alert in self._alerts:
                if alert.id == alert_id:
                    alert.acknowledged = True
                    alert.acknowledged_at = time.time()
                    alert.acknowledged_by = acknowledged_by
                    return True
        return False

    def clear_alerts(self) -> int:
        """Clear all alerts. Returns count cleared."""
        with self._alerts_lock:
            count = len(self._alerts)
            self._alerts.clear()
        return count

    def get_stats(self) -> Dict:
        """Get alert engine statistics."""
        with self._alerts_lock:
            total = len(self._alerts)
            unacked = sum(1 for a in self._alerts if not a.acknowledged)
            by_severity = {}
            for sev in AlertSeverity:
                by_severity[sev.name] = sum(1 for a in self._alerts if a.severity == sev)

        return {
            "total_alerts": total,
            "unacknowledged": unacked,
            "alerts_generated": self.alerts_generated,
            "alerts_suppressed": self.alerts_suppressed,
            "by_severity": by_severity,
            "known_hosts": len(self._known_hosts),
            "blacklist_size": len(self._ip_blacklist),
            "rules_count": len(self._rules),
        }
