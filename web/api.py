"""JSON API endpoints for live dashboard data.

All endpoints return JSON and require authentication via session cookie.
"""

import time
from flask import Blueprint, jsonify, current_app, session, request

api_bp = Blueprint("api", __name__)


def _require_auth():
    """Return error response if not authenticated."""
    if "user_id" not in session:
        return jsonify({"error": "Authentication required"}), 401
    return None


def _get_dashboard():
    """Get the running Dashboard instance."""
    return current_app.config.get("DASHBOARD")


@api_bp.route("/stats")
def stats():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    dash = _get_dashboard()
    if not dash:
        return jsonify({"error": "No active capture session"}), 503

    flow_stats = dash.flow_tracker.get_stats()
    return jsonify({
        "packet_count": dash._packet_count,
        "total_flows": flow_stats.get("total_flows", 0),
        "active_flows": flow_stats.get("active_flows", 0),
        "total_bytes_sent": flow_stats.get("total_bytes_sent", 0),
        "total_bytes_recv": flow_stats.get("total_bytes_recv", 0),
        "uptime": time.time() - getattr(dash, "_start_time", time.time()),
        "paused": dash.paused,
    })


@api_bp.route("/flows")
def flows():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    dash = _get_dashboard()
    if not dash:
        return jsonify([])

    limit = min(int(request.args.get("limit", 100)), 500)
    sort_by = request.args.get("sort", "bytes")

    all_flows = dash.flow_tracker.get_flows()

    if sort_by == "bytes":
        all_flows.sort(key=lambda f: f.total_bytes, reverse=True)
    elif sort_by == "packets":
        all_flows.sort(key=lambda f: f.total_packets, reverse=True)
    elif sort_by == "time":
        all_flows.sort(key=lambda f: f.last_seen, reverse=True)

    flow_list = []
    for flow in all_flows[:limit]:
        # Get anomaly score if available
        anomaly = dash.anomaly_detector.get_score(flow.flow_key)
        anomaly_score = anomaly.total_score if anomaly else 0.0
        anomaly_reasons = anomaly.reasons if anomaly else []

        flow_list.append({
            "flow_key": flow.flow_key,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol_name,
            "packets_sent": flow.packets_sent,
            "packets_recv": flow.packets_recv,
            "bytes_sent": flow.bytes_sent,
            "bytes_recv": flow.bytes_recv,
            "total_bytes": flow.total_bytes,
            "duration": round(flow.duration, 1),
            "first_seen": flow.first_seen,
            "last_seen": flow.last_seen,
            "tags": flow.tags,
            "anomaly_score": round(anomaly_score, 2),
            "anomaly_reasons": anomaly_reasons,
        })

    return jsonify(flow_list)


@api_bp.route("/alerts")
def alerts():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    dash = _get_dashboard()
    if not dash or not dash.alert_engine:
        return jsonify([])

    alert_list = dash.alert_engine.get_alerts()
    return jsonify([
        {
            "id": a.id,
            "type": a.alert_type,
            "severity": a.severity.name if hasattr(a.severity, "name") else str(a.severity),
            "title": a.title,
            "description": a.description,
            "source_ip": a.source_ip,
            "dest_ip": getattr(a, "dest_ip", None),
            "timestamp": a.timestamp,
            "acknowledged": a.acknowledged,
        }
        for a in alert_list
    ])


@api_bp.route("/alerts/ack/<alert_id>", methods=["POST"])
def ack_alert(alert_id):
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    dash = _get_dashboard()
    if dash and dash.alert_engine:
        dash.alert_engine.acknowledge_alert(alert_id)
    return jsonify({"ok": True})


@api_bp.route("/dns")
def dns():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    dash = _get_dashboard()
    if not dash:
        return jsonify({"stats": {}, "top_domains": [], "tunnel_indicators": []})

    dns_stats = dash.dns_tracker.get_summary_stats()
    top_domains = dash.dns_tracker.get_top_queried_domains(limit=20)
    tunnel_indicators = [
        {
            "domain": ind.domain,
            "score": round(ind.score, 2),
            "reasons": ind.reasons,
            "query_count": ind.query_count,
            "subdomain_count": ind.subdomain_count,
            "avg_label_length": round(ind.avg_label_length, 1),
        }
        for ind in dash.dns_tracker.check_tunnel_indicators()
    ]

    return jsonify({
        "stats": dns_stats,
        "top_domains": top_domains,
        "tunnel_indicators": tunnel_indicators,
    })


@api_bp.route("/anomaly")
def anomaly():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    dash = _get_dashboard()
    if not dash:
        return jsonify({"anomalous_flows": [], "beacons": [], "stats": {}})

    anomalous = [
        {
            "flow_key": s.flow_key,
            "score": round(s.total_score, 2),
            "severity": s.severity,
            "reasons": s.reasons,
            "byte_ratio": round(s.byte_ratio_score, 2),
            "duration": round(s.duration_score, 2),
            "packet_size": round(s.packet_size_score, 2),
            "ttl_variance": round(s.ttl_variance_score, 2),
            "connection_rate": round(s.connection_rate_score, 2),
        }
        for s in dash.anomaly_detector.get_anomalous_flows(min_score=0.3)
    ]

    beacons = [
        {
            "src_ip": b.src_ip,
            "dst_ip": b.dst_ip,
            "score": round(b.score, 2),
            "count": b.connection_count,
            "mean_interval": round(b.mean_interval, 1),
            "jitter_pct": round(b.jitter_pct, 1),
        }
        for b in dash.beacon_detector.get_beacons(min_score=0.3)
    ]

    return jsonify({
        "anomalous_flows": anomalous,
        "beacons": beacons,
        "stats": dash.anomaly_detector.get_stats(),
    })


@api_bp.route("/tcp")
def tcp():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    dash = _get_dashboard()
    if not dash or not hasattr(dash, "tcp_tracker"):
        return jsonify({"states": {}, "stats": {}})

    tracker = getattr(dash, "tcp_tracker", None)
    if not tracker:
        return jsonify({"states": {}, "stats": {}})

    return jsonify({
        "states": tracker.get_state_summary(),
        "stats": tracker.get_stats(),
    })


@api_bp.route("/ports")
def ports():
    auth_err = _require_auth()
    if auth_err:
        return auth_err

    dash = _get_dashboard()
    if not dash:
        return jsonify([])

    top_ports = dash.port_tracker.get_top_ports(limit=30)
    return jsonify([
        {
            "port": p.port,
            "protocol": p.protocol,
            "service": dash.port_tracker.get_service_name(p.port) if hasattr(dash.port_tracker, 'get_service_name') else str(p.port),
            "packets_in": p.packets_in,
            "packets_out": p.packets_out,
            "bytes_in": p.bytes_in,
            "bytes_out": p.bytes_out,
        }
        for p in top_ports
    ])
