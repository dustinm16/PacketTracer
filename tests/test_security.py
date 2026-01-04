"""Tests for security module (reputation, alerts, graph)."""

import time
import pytest
from unittest.mock import MagicMock, patch

from security.reputation import (
    ReputationChecker,
    ReputationResult,
    ThreatLevel,
    ABUSEIPDB_CATEGORIES,
)
from security.alerts import (
    AlertEngine,
    Alert,
    AlertRule,
    AlertSeverity,
    AlertType,
    SUSPICIOUS_PORTS,
)
from security.graph import ConnectionGraph, Node, Edge
from tracking.flow import Flow
from tracking.ports import ScanActivity


class TestThreatLevel:
    """Tests for ThreatLevel enum."""

    def test_threat_levels_order(self):
        """Test threat levels are ordered correctly."""
        assert ThreatLevel.UNKNOWN.value < ThreatLevel.CLEAN.value
        assert ThreatLevel.CLEAN.value < ThreatLevel.LOW.value
        assert ThreatLevel.LOW.value < ThreatLevel.MEDIUM.value
        assert ThreatLevel.MEDIUM.value < ThreatLevel.HIGH.value
        assert ThreatLevel.HIGH.value < ThreatLevel.CRITICAL.value


class TestReputationResult:
    """Tests for ReputationResult dataclass."""

    def test_creation(self):
        """Test basic creation."""
        result = ReputationResult(
            ip="8.8.8.8",
            threat_level=ThreatLevel.CLEAN,
            confidence_score=0,
            total_reports=0,
            last_reported=None,
            categories=[],
        )
        assert result.ip == "8.8.8.8"
        assert result.threat_level == ThreatLevel.CLEAN

    def test_is_malicious(self):
        """Test is_malicious property."""
        clean = ReputationResult(
            ip="8.8.8.8",
            threat_level=ThreatLevel.CLEAN,
            confidence_score=0,
            total_reports=0,
            last_reported=None,
            categories=[],
        )
        assert clean.is_malicious is False

        malicious = ReputationResult(
            ip="1.2.3.4",
            threat_level=ThreatLevel.HIGH,
            confidence_score=80,
            total_reports=100,
            last_reported=time.time(),
            categories=["Port Scan", "Brute-Force"],
        )
        assert malicious.is_malicious is True

    def test_is_suspicious(self):
        """Test is_suspicious property."""
        low = ReputationResult(
            ip="1.2.3.4",
            threat_level=ThreatLevel.LOW,
            confidence_score=20,
            total_reports=5,
            last_reported=time.time(),
            categories=[],
        )
        assert low.is_suspicious is True
        assert low.is_malicious is False


class TestReputationChecker:
    """Tests for ReputationChecker class."""

    def test_creation(self):
        """Test checker creation."""
        checker = ReputationChecker()
        assert checker.api_key is None
        assert checker.cache_size == 10000

    def test_creation_with_api_key(self):
        """Test creation with API key."""
        checker = ReputationChecker(api_key="test_key")
        assert checker.api_key == "test_key"

    def test_private_ip_returns_clean(self):
        """Test that private IPs return clean immediately."""
        checker = ReputationChecker()
        result = checker.check_ip("192.168.1.1", async_check=False)

        assert result is not None
        assert result.threat_level == ThreatLevel.CLEAN
        assert result.confidence_score == 0

    def test_caching(self):
        """Test that results are cached."""
        checker = ReputationChecker()

        # Manually cache a result
        result = ReputationResult(
            ip="8.8.8.8",
            threat_level=ThreatLevel.CLEAN,
            confidence_score=0,
            total_reports=0,
            last_reported=None,
            categories=[],
        )
        checker._cache_result(result)

        cached = checker.get_cached("8.8.8.8")
        assert cached is not None
        assert cached.ip == "8.8.8.8"

    def test_get_stats(self):
        """Test statistics collection."""
        checker = ReputationChecker()
        # Private IP check increments checks_total
        result = checker.check_ip("192.168.1.1", async_check=False)

        stats = checker.get_stats()
        assert "cache_size" in stats
        assert "checks_total" in stats
        # Private IPs increment total but may not cache
        assert result is not None

    def test_get_malicious_ips(self):
        """Test getting malicious IPs from cache."""
        checker = ReputationChecker()

        # Manually cache a malicious result
        malicious = ReputationResult(
            ip="1.2.3.4",
            threat_level=ThreatLevel.HIGH,
            confidence_score=80,
            total_reports=100,
            last_reported=time.time(),
            categories=["Brute-Force"],
        )
        checker._cache_result(malicious)

        results = checker.get_malicious_ips()
        assert len(results) == 1
        assert results[0].ip == "1.2.3.4"

    def test_clear_cache(self):
        """Test clearing cache."""
        checker = ReputationChecker()
        checker.check_ip("192.168.1.1", async_check=False)

        checker.clear_cache()

        assert checker.get_cached("192.168.1.1") is None


class TestAlertSeverity:
    """Tests for AlertSeverity enum."""

    def test_severity_order(self):
        """Test severities are ordered correctly."""
        assert AlertSeverity.INFO.value < AlertSeverity.LOW.value
        assert AlertSeverity.LOW.value < AlertSeverity.MEDIUM.value
        assert AlertSeverity.MEDIUM.value < AlertSeverity.HIGH.value
        assert AlertSeverity.HIGH.value < AlertSeverity.CRITICAL.value


class TestAlert:
    """Tests for Alert dataclass."""

    def test_creation(self):
        """Test alert creation."""
        alert = Alert(
            id="ALT-001",
            alert_type=AlertType.PORT_SCAN,
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            description="Test description",
            source_ip="192.168.1.100",
        )
        assert alert.id == "ALT-001"
        assert alert.alert_type == AlertType.PORT_SCAN
        assert alert.acknowledged is False

    def test_to_dict(self):
        """Test alert serialization."""
        alert = Alert(
            id="ALT-001",
            alert_type=AlertType.PORT_SCAN,
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            description="Test description",
        )
        data = alert.to_dict()

        assert data["id"] == "ALT-001"
        assert data["type"] == "port_scan"
        assert data["severity"] == "HIGH"


class TestAlertRule:
    """Tests for AlertRule dataclass."""

    def test_creation(self):
        """Test rule creation."""
        rule = AlertRule(
            name="test_rule",
            alert_type=AlertType.PORT_SCAN,
        )
        assert rule.name == "test_rule"
        assert rule.enabled is True

    def test_matches_ip(self):
        """Test IP matching."""
        rule = AlertRule(
            name="test",
            alert_type=AlertType.PORT_SCAN,
            include_ips=["192.168.1.1", "192.168.1.2"],
        )
        assert rule.matches_ip("192.168.1.1") is True
        assert rule.matches_ip("192.168.1.3") is False

    def test_matches_ip_exclude(self):
        """Test IP exclusion."""
        rule = AlertRule(
            name="test",
            alert_type=AlertType.PORT_SCAN,
            exclude_ips=["10.0.0.1"],
        )
        assert rule.matches_ip("10.0.0.1") is False
        assert rule.matches_ip("192.168.1.1") is True

    def test_matches_port(self):
        """Test port matching."""
        rule = AlertRule(
            name="test",
            alert_type=AlertType.SUSPICIOUS_PORT,
            include_ports=[22, 23, 3389],
        )
        assert rule.matches_port(22) is True
        assert rule.matches_port(80) is False


class TestAlertEngine:
    """Tests for AlertEngine class."""

    @pytest.fixture
    def engine(self):
        """Create alert engine fixture."""
        return AlertEngine(max_alerts=100)

    def test_creation(self, engine):
        """Test engine creation."""
        assert engine.max_alerts == 100
        assert len(engine._rules) > 0  # Default rules loaded

    def test_default_rules_loaded(self, engine):
        """Test that default rules are loaded."""
        rules = engine.get_rules()
        rule_names = [r.name for r in rules]

        assert "port_scan_detection" in rule_names
        assert "high_bandwidth" in rule_names
        assert "suspicious_port_access" in rule_names

    def test_add_rule(self, engine):
        """Test adding a custom rule."""
        rule = AlertRule(
            name="custom_rule",
            alert_type=AlertType.CUSTOM,
            severity=AlertSeverity.MEDIUM,
        )
        engine.add_rule(rule)

        rules = engine.get_rules()
        assert any(r.name == "custom_rule" for r in rules)

    def test_remove_rule(self, engine):
        """Test removing a rule."""
        result = engine.remove_rule("port_scan_detection")
        assert result is True

        rules = engine.get_rules()
        assert not any(r.name == "port_scan_detection" for r in rules)

    def test_enable_disable_rule(self, engine):
        """Test enabling/disabling rules."""
        engine.enable_rule("port_scan_detection", False)

        rule = next(r for r in engine.get_rules() if r.name == "port_scan_detection")
        assert rule.enabled is False

    def test_blacklist_management(self, engine):
        """Test IP blacklist management."""
        engine.add_to_blacklist("1.2.3.4")
        assert engine.is_blacklisted("1.2.3.4") is True

        engine.remove_from_blacklist("1.2.3.4")
        assert engine.is_blacklisted("1.2.3.4") is False

    def test_check_scan_activity(self, engine):
        """Test port scan detection."""
        activity = ScanActivity(src_ip="192.168.1.100")
        activity.ports_hit = set(range(1, 25))  # 24 ports
        activity.first_seen = time.time() - 10
        activity.last_seen = time.time()

        alert = engine.check_scan_activity(activity)

        assert alert is not None
        assert alert.alert_type == AlertType.PORT_SCAN
        assert alert.source_ip == "192.168.1.100"

    def test_check_suspicious_port(self, engine):
        """Test suspicious port detection."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=23,  # Telnet - suspicious
            protocol=6,
            protocol_name="TCP",
        )

        alerts = engine.check_flow(flow)

        suspicious_alerts = [a for a in alerts if a.alert_type == AlertType.SUSPICIOUS_PORT]
        assert len(suspicious_alerts) >= 1

    def test_check_blacklisted_ip(self, engine):
        """Test blacklisted IP detection."""
        engine.add_to_blacklist("1.2.3.4")

        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="1.2.3.4",
            src_port=54321,
            dst_port=80,
            protocol=6,
            protocol_name="TCP",
        )

        alerts = engine.check_flow(flow)

        blacklist_alerts = [a for a in alerts if a.alert_type == AlertType.BLACKLISTED_IP]
        assert len(blacklist_alerts) >= 1

    def test_cooldown(self, engine):
        """Test alert cooldown prevents spam."""
        activity = ScanActivity(src_ip="192.168.1.100")
        activity.ports_hit = set(range(1, 25))

        # First alert should trigger
        alert1 = engine.check_scan_activity(activity)
        assert alert1 is not None

        # Second immediate check should be suppressed
        alert2 = engine.check_scan_activity(activity)
        assert alert2 is None

    def test_get_alerts(self, engine):
        """Test getting alerts with filters."""
        # Generate some alerts
        activity = ScanActivity(src_ip="192.168.1.100")
        activity.ports_hit = set(range(1, 25))
        engine.check_scan_activity(activity)

        alerts = engine.get_alerts(limit=10)
        assert len(alerts) >= 1

    def test_acknowledge_alert(self, engine):
        """Test acknowledging alerts."""
        activity = ScanActivity(src_ip="192.168.1.100")
        activity.ports_hit = set(range(1, 25))
        alert = engine.check_scan_activity(activity)

        result = engine.acknowledge_alert(alert.id, "test_user")
        assert result is True

        updated = engine.get_alert(alert.id)
        assert updated.acknowledged is True
        assert updated.acknowledged_by == "test_user"

    def test_get_stats(self, engine):
        """Test engine statistics."""
        stats = engine.get_stats()

        assert "total_alerts" in stats
        assert "alerts_generated" in stats
        assert "rules_count" in stats


class TestConnectionGraph:
    """Tests for ConnectionGraph class."""

    @pytest.fixture
    def graph(self):
        """Create graph fixture."""
        return ConnectionGraph()

    def test_creation(self, graph):
        """Test graph creation."""
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_add_flow(self, graph):
        """Test adding a flow."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            bytes_sent=1000,
            bytes_recv=5000,
        )
        graph.add_flow(flow)

        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1
        assert "192.168.1.100" in graph.nodes
        assert "8.8.8.8" in graph.nodes

    def test_add_multiple_flows(self, graph):
        """Test adding multiple flows."""
        flows = [
            Flow(src_ip="192.168.1.100", dst_ip="8.8.8.8", src_port=54321, dst_port=443, protocol=6, protocol_name="TCP"),
            Flow(src_ip="192.168.1.100", dst_ip="1.1.1.1", src_port=54322, dst_port=53, protocol=17, protocol_name="UDP"),
            Flow(src_ip="192.168.1.101", dst_ip="8.8.8.8", src_port=54323, dst_port=443, protocol=6, protocol_name="TCP"),
        ]
        graph.add_flows(flows)

        assert len(graph.nodes) == 4
        assert len(graph.edges) == 3

    def test_node_properties(self, graph):
        """Test node properties."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            bytes_sent=1000,
            bytes_recv=5000,
        )
        graph.add_flow(flow)

        src_node = graph.nodes["192.168.1.100"]
        assert src_node.is_local is True
        assert src_node.total_bytes_out == 1000

        dst_node = graph.nodes["8.8.8.8"]
        assert dst_node.is_local is False
        assert dst_node.total_bytes_in == 1000

    def test_set_hostname(self, graph):
        """Test setting hostname."""
        flow = Flow(src_ip="192.168.1.100", dst_ip="8.8.8.8", src_port=1, dst_port=443, protocol=6, protocol_name="TCP")
        graph.add_flow(flow)
        graph.set_hostname("8.8.8.8", "dns.google")

        node = graph.nodes["8.8.8.8"]
        assert node.hostname == "dns.google"
        assert "dns.google" in node.label

    def test_render_simple(self, graph):
        """Test simple rendering."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            bytes_sent=1000,
            bytes_recv=5000,
        )
        graph.add_flow(flow)

        output = graph.render_simple()
        assert "CONNECTION GRAPH" in output
        assert "192.168.1.100" in output
        assert "8.8.8.8" in output

    def test_render_stats(self, graph):
        """Test stats rendering."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            bytes_sent=1000,
            bytes_recv=5000,
        )
        graph.add_flow(flow)

        output = graph.render_stats()
        assert "GRAPH STATISTICS" in output
        assert "Total Nodes:" in output

    def test_get_summary(self, graph):
        """Test summary generation."""
        flow = Flow(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=6,
            protocol_name="TCP",
            bytes_sent=1000,
            bytes_recv=5000,
        )
        graph.add_flow(flow)

        summary = graph.get_summary()
        assert summary["total_nodes"] == 2
        assert summary["local_nodes"] == 1
        assert summary["external_nodes"] == 1
        assert summary["total_edges"] == 1

    def test_clear(self, graph):
        """Test clearing graph."""
        flow = Flow(src_ip="192.168.1.100", dst_ip="8.8.8.8", src_port=1, dst_port=443, protocol=6, protocol_name="TCP")
        graph.add_flow(flow)

        graph.clear()

        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0


class TestSuspiciousPorts:
    """Tests for suspicious ports constant."""

    def test_common_suspicious_ports(self):
        """Test that common suspicious ports are defined."""
        assert 23 in SUSPICIOUS_PORTS  # Telnet
        assert 445 in SUSPICIOUS_PORTS  # SMB
        assert 3389 in SUSPICIOUS_PORTS  # RDP
        assert 5900 in SUSPICIOUS_PORTS  # VNC
