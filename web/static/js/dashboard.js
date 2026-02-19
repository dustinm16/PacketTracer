/* PacketTracer Web UI — Live data refresh */

const REFRESH_MS = 3000;
let refreshTimer = null;

/* -- Helpers -- */
function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatNumber(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
    return String(n);
}

function timeSince(ts) {
    const s = Math.floor(Date.now() / 1000 - ts);
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
}

function severityBadge(severity) {
    const cls = {
        critical: "badge-critical",
        high: "badge-high",
        medium: "badge-medium",
        low: "badge-low",
        info: "badge-info",
    }[severity] || "badge-info";
    return `<span class="badge ${cls}">${severity}</span>`;
}

function scoreBar(score) {
    const pct = Math.round(score * 100);
    let cls = "score-low";
    if (score >= 0.8) cls = "score-critical";
    else if (score >= 0.6) cls = "score-high";
    else if (score >= 0.4) cls = "score-medium";
    return `<span class="score-bar"><span class="score-fill ${cls}" style="width:${pct}%"></span></span>${pct}%`;
}

function tagSpan(tag) {
    let cls = "tag";
    if (tag === "anomalous") cls += " tag-anomalous";
    else if (tag.startsWith("malicious")) cls += " tag-malicious";
    else if (tag.startsWith("suspicious")) cls += " tag-suspicious";
    return `<span class="${cls}">${tag}</span>`;
}

/* -- API fetch wrapper -- */
async function apiFetch(endpoint) {
    try {
        const resp = await fetch("/api" + endpoint);
        if (resp.status === 401) {
            window.location.href = "/auth/login";
            return null;
        }
        return await resp.json();
    } catch (e) {
        console.error("API error:", e);
        return null;
    }
}

/* -- Dashboard page -- */
async function refreshDashboard() {
    const stats = await apiFetch("/stats");
    if (!stats) return;

    setTextIfExists("stat-packets", formatNumber(stats.packet_count || 0));
    setTextIfExists("stat-flows", formatNumber(stats.total_flows || 0));
    setTextIfExists("stat-active", formatNumber(stats.active_flows || 0));
    setTextIfExists("stat-bytes", formatBytes((stats.total_bytes_sent || 0) + (stats.total_bytes_recv || 0)));

    const statusEl = document.getElementById("capture-status");
    if (statusEl) {
        if (stats.paused) {
            statusEl.innerHTML = '<span class="pulse pulse-yellow"></span>Paused';
        } else {
            statusEl.innerHTML = '<span class="pulse pulse-green"></span>Capturing';
        }
    }

    // Recent anomalies summary
    const anomaly = await apiFetch("/anomaly");
    if (anomaly) {
        setTextIfExists("stat-anomalies", String(anomaly.stats.anomalous_flows || 0));
        setTextIfExists("stat-beacons", String(anomaly.beacons.length));
    }

    // Alert count
    const alerts = await apiFetch("/alerts");
    if (alerts) {
        const unacked = alerts.filter(a => !a.acknowledged).length;
        setTextIfExists("stat-alerts", String(unacked));
    }
}

/* -- Flows page -- */
async function refreshFlows() {
    const flows = await apiFetch("/flows?limit=100&sort=bytes");
    if (!flows) return;

    const tbody = document.getElementById("flows-tbody");
    if (!tbody) return;

    tbody.innerHTML = flows.map(f => `
        <tr>
            <td>${f.src_ip}:${f.src_port}</td>
            <td>${f.dst_ip}:${f.dst_port}</td>
            <td>${f.protocol}</td>
            <td>${formatBytes(f.bytes_sent)}</td>
            <td>${formatBytes(f.bytes_recv)}</td>
            <td>${formatNumber(f.packets_sent + f.packets_recv)}</td>
            <td>${f.duration}s</td>
            <td>${f.anomaly_score > 0 ? scoreBar(f.anomaly_score) : '<span class="text-muted">-</span>'}</td>
            <td>${f.tags.map(tagSpan).join(" ") || "-"}</td>
        </tr>
    `).join("");
}

/* -- Alerts page -- */
async function refreshAlerts() {
    const alerts = await apiFetch("/alerts");
    if (!alerts) return;

    const tbody = document.getElementById("alerts-tbody");
    if (!tbody) return;

    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td>${severityBadge(a.severity)}</td>
            <td>${a.type}</td>
            <td>${a.title}</td>
            <td>${a.source_ip || "-"}</td>
            <td>${timeSince(a.timestamp)}</td>
            <td>
                ${a.acknowledged
                    ? '<span class="badge badge-info">Acked</span>'
                    : `<button class="btn btn-sm" onclick="ackAlert('${a.id}')">Ack</button>`}
            </td>
        </tr>
    `).join("");
}

async function ackAlert(alertId) {
    await fetch("/api/alerts/ack/" + alertId, { method: "POST" });
    refreshAlerts();
}

/* -- DNS page -- */
async function refreshDNS() {
    const data = await apiFetch("/dns");
    if (!data) return;

    setTextIfExists("dns-queries", formatNumber(data.stats.total_queries || 0));
    setTextIfExists("dns-responses", formatNumber(data.stats.total_responses || 0));
    setTextIfExists("dns-nxdomain", formatNumber(data.stats.nxdomain_count || 0));

    const domainTbody = document.getElementById("dns-domains-tbody");
    if (domainTbody && data.top_domains) {
        domainTbody.innerHTML = data.top_domains.map(d => `
            <tr>
                <td>${d.query_name || d.domain || "-"}</td>
                <td>${d.query_count || d.count || 0}</td>
                <td>${d.response_count || "-"}</td>
                <td>${d.nxdomain_count || 0}</td>
            </tr>
        `).join("");
    }

    const tunnelTbody = document.getElementById("dns-tunnel-tbody");
    if (tunnelTbody) {
        tunnelTbody.innerHTML = data.tunnel_indicators.map(t => `
            <tr>
                <td>${t.domain}</td>
                <td>${scoreBar(t.score)}</td>
                <td>${t.query_count}</td>
                <td>${t.subdomain_count}</td>
                <td>${t.avg_label_length}</td>
                <td><ul class="reason-list">${t.reasons.map(r => `<li>${r}</li>`).join("")}</ul></td>
            </tr>
        `).join("");
    }
}

/* -- Anomaly page -- */
async function refreshAnomaly() {
    const data = await apiFetch("/anomaly");
    if (!data) return;

    setTextIfExists("anomaly-scored", formatNumber(data.stats.scored_flows || 0));
    setTextIfExists("anomaly-flagged", String(data.stats.anomalous_flows || 0));
    setTextIfExists("anomaly-tracked-ips", formatNumber(data.stats.tracked_ips || 0));

    const flowsTbody = document.getElementById("anomaly-flows-tbody");
    if (flowsTbody) {
        flowsTbody.innerHTML = data.anomalous_flows.map(f => `
            <tr>
                <td>${f.flow_key}</td>
                <td>${scoreBar(f.score)}</td>
                <td>${severityBadge(f.severity)}</td>
                <td><ul class="reason-list">${f.reasons.map(r => `<li>${r}</li>`).join("")}</ul></td>
            </tr>
        `).join("");
    }

    const beaconTbody = document.getElementById("beacon-tbody");
    if (beaconTbody) {
        beaconTbody.innerHTML = data.beacons.map(b => `
            <tr>
                <td>${b.src_ip}</td>
                <td>${b.dst_ip}</td>
                <td>${scoreBar(b.score)}</td>
                <td>${b.count}</td>
                <td>${b.mean_interval}s</td>
                <td>${b.jitter_pct}%</td>
            </tr>
        `).join("");
    }
}

/* -- Utility -- */
function setTextIfExists(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

/* -- Auto-refresh router -- */
function startRefresh() {
    const page = document.body.dataset.page;
    const fn = {
        dashboard: refreshDashboard,
        flows: refreshFlows,
        alerts: refreshAlerts,
        dns: refreshDNS,
        anomaly: refreshAnomaly,
    }[page];

    if (fn) {
        fn();
        refreshTimer = setInterval(fn, REFRESH_MS);
    }
}

document.addEventListener("DOMContentLoaded", startRefresh);
