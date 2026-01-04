"""Database schema definitions and migrations."""

SCHEMA_VERSION = 5

SCHEMA_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

-- Sessions for historical tracking
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    ended_at REAL,
    interface TEXT,
    bpf_filter TEXT,
    total_packets INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC);

-- Flows with denormalized geo/dns/classification data
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    flow_key TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    protocol_name TEXT NOT NULL,
    packets_sent INTEGER DEFAULT 0,
    packets_recv INTEGER DEFAULT 0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_recv INTEGER DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    min_ttl INTEGER DEFAULT 255,
    max_ttl INTEGER DEFAULT 0,
    -- Denormalized source geo
    src_country TEXT,
    src_country_code TEXT,
    src_city TEXT,
    src_isp TEXT,
    src_as_name TEXT,
    -- Denormalized destination geo
    dst_country TEXT,
    dst_country_code TEXT,
    dst_city TEXT,
    dst_isp TEXT,
    dst_as_name TEXT,
    -- DNS resolution
    src_hostname TEXT,
    src_domain TEXT,
    src_fqdn TEXT,
    dst_hostname TEXT,
    dst_domain TEXT,
    dst_fqdn TEXT,
    -- Classification
    category TEXT,
    subcategory TEXT,
    service TEXT,
    is_encrypted INTEGER DEFAULT 0,
    classification_confidence REAL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_flows_unique_key ON flows(session_id, flow_key);
CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(session_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_flows_bytes ON flows(session_id, bytes_sent + bytes_recv DESC);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip);

-- Port statistics
CREATE TABLE IF NOT EXISTS port_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packets_in INTEGER DEFAULT 0,
    packets_out INTEGER DEFAULT 0,
    bytes_in INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0,
    hit_count INTEGER DEFAULT 0,
    unique_sources INTEGER DEFAULT 0,
    unique_destinations INTEGER DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_port_stats_unique ON port_stats(session_id, port, protocol);
CREATE INDEX IF NOT EXISTS idx_port_stats_bytes ON port_stats(session_id, bytes_in + bytes_out DESC);

-- Persistent geo cache (survives restarts)
CREATE TABLE IF NOT EXISTS geo_cache (
    ip TEXT PRIMARY KEY,
    country TEXT,
    country_code TEXT,
    region TEXT,
    city TEXT,
    zip_code TEXT,
    latitude REAL,
    longitude REAL,
    timezone TEXT,
    isp TEXT,
    org TEXT,
    as_number TEXT,
    as_name TEXT,
    is_private INTEGER DEFAULT 0,
    query_success INTEGER DEFAULT 1,
    cached_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_geo_expires ON geo_cache(expires_at);

-- Persistent DNS cache
CREATE TABLE IF NOT EXISTS dns_cache (
    ip TEXT PRIMARY KEY,
    hostname TEXT,       -- Short hostname (first part)
    domain TEXT,         -- Base domain (e.g., "example.com")
    fqdn TEXT,           -- Full Qualified Domain Name
    resolved INTEGER DEFAULT 0,
    cached_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dns_expires ON dns_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_dns_fqdn ON dns_cache(fqdn);

-- DNS queries (captured DNS traffic)
CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    transaction_id INTEGER NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    query_name TEXT NOT NULL,
    query_type INTEGER NOT NULL,
    query_type_name TEXT NOT NULL,
    is_response INTEGER NOT NULL,
    response_code INTEGER,
    response_code_name TEXT,
    answer_count INTEGER DEFAULT 0,
    answers TEXT,              -- JSON array of answers
    latency_ms REAL,           -- Response latency if matched
    is_nxdomain INTEGER DEFAULT 0,
    is_error INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_dns_queries_session ON dns_queries(session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_dns_queries_name ON dns_queries(query_name);
CREATE INDEX IF NOT EXISTS idx_dns_queries_type ON dns_queries(query_type_name);
CREATE INDEX IF NOT EXISTS idx_dns_queries_nxdomain ON dns_queries(session_id, is_nxdomain) WHERE is_nxdomain = 1;

-- DNS query statistics (aggregated per domain)
CREATE TABLE IF NOT EXISTS dns_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    query_name TEXT NOT NULL,
    query_count INTEGER DEFAULT 0,
    response_count INTEGER DEFAULT 0,
    nxdomain_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    avg_latency_ms REAL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    unique_query_types TEXT,   -- Comma-separated list of query types
    resolved_ips TEXT,         -- Comma-separated list of resolved IPs
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_stats_unique ON dns_stats(session_id, query_name);
CREATE INDEX IF NOT EXISTS idx_dns_stats_count ON dns_stats(session_id, query_count DESC);

-- Scan activity tracking
CREATE TABLE IF NOT EXISTS scan_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    src_ip TEXT NOT NULL,
    ports_hit TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    packet_count INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_unique ON scan_activity(session_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_scan_session ON scan_activity(session_id);

-- Traffic classifications (separate table for flexibility)
CREATE TABLE IF NOT EXISTS classifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    flow_key TEXT NOT NULL,
    category TEXT NOT NULL,
    confidence REAL,
    subcategory TEXT,
    service TEXT,
    is_encrypted INTEGER DEFAULT 0,
    description TEXT,
    classified_at REAL NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_classifications_unique ON classifications(session_id, flow_key);

-- Traceroute sessions
CREATE TABLE IF NOT EXISTS traceroutes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    target_ip TEXT NOT NULL,
    target_hostname TEXT,
    started_at REAL NOT NULL,
    completed_at REAL,
    total_hops INTEGER DEFAULT 0,
    reached_target INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_traceroutes_session ON traceroutes(session_id);
CREATE INDEX IF NOT EXISTS idx_traceroutes_target ON traceroutes(target_ip);

-- Hop nodes with latency tracking
CREATE TABLE IF NOT EXISTS hops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    traceroute_id INTEGER NOT NULL,
    hop_number INTEGER NOT NULL,
    ip TEXT,
    hostname TEXT,
    domain TEXT,
    -- Latency measurements (multiple probes per hop)
    rtt_min REAL,
    rtt_max REAL,
    rtt_avg REAL,
    rtt_samples INTEGER DEFAULT 0,
    -- Packet loss
    probes_sent INTEGER DEFAULT 0,
    probes_received INTEGER DEFAULT 0,
    loss_percent REAL DEFAULT 0.0,
    -- Geo data for hop node
    country TEXT,
    country_code TEXT,
    city TEXT,
    isp TEXT,
    as_name TEXT,
    as_number TEXT,
    latitude REAL,
    longitude REAL,
    -- Status
    is_timeout INTEGER DEFAULT 0,
    is_target INTEGER DEFAULT 0,
    measured_at REAL NOT NULL,
    FOREIGN KEY (traceroute_id) REFERENCES traceroutes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hops_traceroute ON hops(traceroute_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hops_unique ON hops(traceroute_id, hop_number);

-- Latency samples (for detailed RTT history per hop)
CREATE TABLE IF NOT EXISTS latency_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hop_id INTEGER NOT NULL,
    rtt REAL NOT NULL,
    probe_number INTEGER NOT NULL,
    measured_at REAL NOT NULL,
    FOREIGN KEY (hop_id) REFERENCES hops(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_latency_hop ON latency_samples(hop_id);

-- Network path summary (aggregated path info for quick lookups)
CREATE TABLE IF NOT EXISTS path_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    hop_count INTEGER DEFAULT 0,
    avg_latency REAL,
    total_latency REAL,
    path_hash TEXT,  -- Hash of hop IPs for path comparison
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    sample_count INTEGER DEFAULT 1,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_path_summary_session ON path_summary(session_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_path_summary_unique ON path_summary(session_id, src_ip, dst_ip);

-- Device details storage (persistent across sessions)
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    mac TEXT,
    -- Device classification
    device_type TEXT DEFAULT 'unknown',  -- endpoint, router, switch, firewall, server, iot, etc.
    device_role TEXT,  -- gateway, dns_server, web_server, workstation, etc.
    -- Identification
    hostname TEXT,
    domain TEXT,
    manufacturer TEXT,  -- From MAC OUI lookup
    device_name TEXT,  -- User-assigned friendly name
    -- Network info
    is_local INTEGER DEFAULT 0,
    is_gateway INTEGER DEFAULT 0,
    subnet TEXT,
    vlan INTEGER,
    -- Discovery info
    ttl_signature INTEGER,  -- For OS fingerprinting
    os_guess TEXT,
    -- Metadata
    notes TEXT,
    tags TEXT,  -- JSON array of tags
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_updated REAL NOT NULL,
    UNIQUE(ip)
);

CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);
CREATE INDEX IF NOT EXISTS idx_devices_role ON devices(device_role);

-- Node ownership for network infrastructure
CREATE TABLE IF NOT EXISTS node_ownership (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    -- Ownership data
    owner TEXT,  -- Organization/person owning this node
    operator TEXT,  -- Who operates/manages it
    contact TEXT,  -- Contact info
    -- Network ownership (from WHOIS/ASN)
    asn TEXT,
    as_name TEXT,
    org TEXT,
    isp TEXT,
    network_cidr TEXT,
    -- Management
    management_url TEXT,
    management_protocol TEXT,  -- ssh, telnet, https, snmp
    is_managed INTEGER DEFAULT 0,
    -- Metadata
    notes TEXT,
    tags TEXT,
    first_seen REAL NOT NULL,
    last_updated REAL NOT NULL,
    UNIQUE(ip)
);

CREATE INDEX IF NOT EXISTS idx_node_ownership_ip ON node_ownership(ip);
CREATE INDEX IF NOT EXISTS idx_node_ownership_asn ON node_ownership(asn);

-- NS lookup cache (domain name server records)
CREATE TABLE IF NOT EXISTS ns_lookup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL,  -- A, AAAA, NS, MX, TXT, CNAME, SOA, PTR
    record_value TEXT NOT NULL,
    ttl INTEGER,
    -- For MX records
    priority INTEGER,
    -- Metadata
    cached_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    query_success INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_ns_lookup_domain ON ns_lookup(domain);
CREATE INDEX IF NOT EXISTS idx_ns_lookup_type ON ns_lookup(domain, record_type);
CREATE INDEX IF NOT EXISTS idx_ns_lookup_expires ON ns_lookup(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ns_lookup_unique ON ns_lookup(domain, record_type, record_value);

-- Route patterns (for tracking repeated routes)
CREATE TABLE IF NOT EXISTS route_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    -- Route signature
    path_hash TEXT NOT NULL,  -- Hash of hop IPs
    hop_ips TEXT NOT NULL,  -- JSON array of hop IPs
    hop_count INTEGER NOT NULL,
    -- Statistics
    times_seen INTEGER DEFAULT 1,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    -- Latency stats
    avg_total_latency REAL,
    min_total_latency REAL,
    max_total_latency REAL,
    -- Stability
    is_stable INTEGER DEFAULT 1,  -- Has the route changed?
    UNIQUE(src_ip, dst_ip, path_hash)
);

CREATE INDEX IF NOT EXISTS idx_route_patterns_src ON route_patterns(src_ip);
CREATE INDEX IF NOT EXISTS idx_route_patterns_dst ON route_patterns(dst_ip);
CREATE INDEX IF NOT EXISTS idx_route_patterns_stable ON route_patterns(is_stable);

-- Route changes log (for tracking when routes change)
CREATE TABLE IF NOT EXISTS route_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    old_path_hash TEXT,
    new_path_hash TEXT NOT NULL,
    old_hop_count INTEGER,
    new_hop_count INTEGER NOT NULL,
    changed_at REAL NOT NULL,
    -- What changed
    change_type TEXT,  -- new, hop_added, hop_removed, hop_changed, path_shift
    change_details TEXT  -- JSON with details
);

CREATE INDEX IF NOT EXISTS idx_route_changes_time ON route_changes(changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_route_changes_dst ON route_changes(dst_ip);

-- Relay agents (remote monitoring agents)
CREATE TABLE IF NOT EXISTS relay_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL UNIQUE,      -- UUID for the agent
    name TEXT NOT NULL,                  -- Human-readable name
    hardware_id TEXT NOT NULL,           -- MAC address or machine-id (for binding)
    token_hash TEXT NOT NULL,            -- Hashed authentication token
    hostname TEXT,                       -- Agent hostname
    ip_address TEXT,                     -- Last known IP
    os_type TEXT,                        -- linux, windows, macos
    os_version TEXT,
    python_version TEXT,
    agent_version TEXT,
    -- Status
    status TEXT DEFAULT 'pending',       -- pending, active, offline, revoked
    last_seen REAL,
    last_heartbeat REAL,
    -- Timestamps
    created_at REAL NOT NULL,
    activated_at REAL,
    revoked_at REAL,
    -- Config
    config TEXT                          -- JSON config for agent
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_relay_agents_id ON relay_agents(agent_id);
CREATE INDEX IF NOT EXISTS idx_relay_agents_hardware ON relay_agents(hardware_id);
CREATE INDEX IF NOT EXISTS idx_relay_agents_status ON relay_agents(status);

-- Relay agent events (connection events, errors, etc.)
CREATE TABLE IF NOT EXISTS relay_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,            -- connect, disconnect, error, heartbeat, auth_fail
    event_data TEXT,                     -- JSON event details
    ip_address TEXT,
    timestamp REAL NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES relay_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_relay_events_agent ON relay_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_relay_events_time ON relay_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_relay_events_type ON relay_events(event_type);

-- Relay agent metrics (system metrics from agents)
CREATE TABLE IF NOT EXISTS relay_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    metric_type TEXT NOT NULL,           -- cpu, memory, disk, network, packets
    metric_data TEXT NOT NULL,           -- JSON metric data
    timestamp REAL NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES relay_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_relay_metrics_agent ON relay_metrics(agent_id);
CREATE INDEX IF NOT EXISTS idx_relay_metrics_time ON relay_metrics(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_relay_metrics_type ON relay_metrics(metric_type);

-- Relay captured flows (flows captured by remote agents)
CREATE TABLE IF NOT EXISTS relay_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    flow_key TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    packets_sent INTEGER DEFAULT 0,
    packets_recv INTEGER DEFAULT 0,
    bytes_sent INTEGER DEFAULT 0,
    bytes_recv INTEGER DEFAULT 0,
    first_seen REAL,
    last_seen REAL,
    -- Agent can include geo/dns if it has resolvers
    dst_country TEXT,
    dst_hostname TEXT,
    FOREIGN KEY (agent_id) REFERENCES relay_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_relay_flows_agent ON relay_flows(agent_id);
CREATE INDEX IF NOT EXISTS idx_relay_flows_time ON relay_flows(last_seen DESC);

-- IP Reputation cache
CREATE TABLE IF NOT EXISTS reputation_cache (
    ip TEXT PRIMARY KEY,
    threat_level TEXT NOT NULL,
    confidence_score INTEGER DEFAULT 0,
    total_reports INTEGER DEFAULT 0,
    last_reported REAL,
    categories TEXT,  -- JSON array
    isp TEXT,
    domain TEXT,
    country_code TEXT,
    is_tor INTEGER DEFAULT 0,
    is_vpn INTEGER DEFAULT 0,
    is_proxy INTEGER DEFAULT 0,
    is_datacenter INTEGER DEFAULT 0,
    cached_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reputation_expires ON reputation_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_reputation_threat ON reputation_cache(threat_level);

-- Security alerts
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    session_id INTEGER,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    port INTEGER,
    protocol TEXT,
    flow_key TEXT,
    details TEXT,  -- JSON
    timestamp REAL NOT NULL,
    acknowledged INTEGER DEFAULT 0,
    acknowledged_at REAL,
    acknowledged_by TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_unacked ON alerts(acknowledged) WHERE acknowledged = 0;
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_ip);

-- IP Blacklist
CREATE TABLE IF NOT EXISTS ip_blacklist (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    added_at REAL NOT NULL,
    added_by TEXT,
    expires_at REAL,  -- NULL for permanent
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_blacklist_active ON ip_blacklist(is_active);
"""


def init_schema(pool_or_conn) -> None:
    """Initialize the database schema.

    Args:
        pool_or_conn: ConnectionPool instance or raw sqlite3.Connection
    """
    import time

    # Handle both ConnectionPool and raw connection
    if hasattr(pool_or_conn, 'write_connection'):
        # It's a ConnectionPool
        with pool_or_conn.write_connection() as conn:
            _init_schema_internal(conn)
    else:
        # It's a raw connection
        _init_schema_internal(pool_or_conn)


def _init_schema_internal(conn) -> None:
    """Internal schema initialization on a raw connection."""
    import time

    # Check if schema already exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    )
    if cursor.fetchone() is None:
        # Fresh database, create all tables
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            [SCHEMA_VERSION, time.time()]
        )
        conn.commit()
    else:
        # Check version and migrate if needed
        cursor = conn.execute("SELECT MAX(version) FROM schema_version")
        current_version = cursor.fetchone()[0] or 0
        if current_version < SCHEMA_VERSION:
            _migrate(conn, current_version, SCHEMA_VERSION)


def _migrate(conn, from_version: int, to_version: int) -> None:
    """Run migrations from one version to another."""
    import time

    # Run migrations sequentially
    if from_version < 2 and to_version >= 2:
        _migrate_v1_to_v2(conn)

    if from_version < 3 and to_version >= 3:
        _migrate_v2_to_v3(conn)

    if from_version < 4 and to_version >= 4:
        _migrate_v3_to_v4(conn)

    if from_version < 5 and to_version >= 5:
        _migrate_v4_to_v5(conn)

    # Record new version
    conn.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
        [to_version, time.time()]
    )
    conn.commit()


def _migrate_v1_to_v2(conn) -> None:
    """Migration: Add FQDN column to dns_cache and flows tables."""
    # Add fqdn column to dns_cache if not exists
    try:
        conn.execute("ALTER TABLE dns_cache ADD COLUMN fqdn TEXT")
    except Exception:
        pass  # Column might already exist

    # Add fqdn columns to flows table
    try:
        conn.execute("ALTER TABLE flows ADD COLUMN src_fqdn TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE flows ADD COLUMN dst_fqdn TEXT")
    except Exception:
        pass

    # Create index on fqdn
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_fqdn ON dns_cache(fqdn)")
    except Exception:
        pass


def _migrate_v2_to_v3(conn) -> None:
    """Migration: Add DNS query tracking tables."""
    # Create dns_queries table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            transaction_id INTEGER NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            query_name TEXT NOT NULL,
            query_type INTEGER NOT NULL,
            query_type_name TEXT NOT NULL,
            is_response INTEGER NOT NULL,
            response_code INTEGER,
            response_code_name TEXT,
            answer_count INTEGER DEFAULT 0,
            answers TEXT,
            latency_ms REAL,
            is_nxdomain INTEGER DEFAULT 0,
            is_error INTEGER DEFAULT 0,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        )
    """)

    # Create dns_stats table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dns_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            query_name TEXT NOT NULL,
            query_count INTEGER DEFAULT 0,
            response_count INTEGER DEFAULT 0,
            nxdomain_count INTEGER DEFAULT 0,
            error_count INTEGER DEFAULT 0,
            avg_latency_ms REAL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            unique_query_types TEXT,
            resolved_ips TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        )
    """)

    # Create indexes
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_queries_session ON dns_queries(session_id, timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_queries_name ON dns_queries(query_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_queries_type ON dns_queries(query_type_name)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_stats_unique ON dns_stats(session_id, query_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_stats_count ON dns_stats(session_id, query_count DESC)")
    except Exception:
        pass


def _migrate_v3_to_v4(conn) -> None:
    """Migration: Add relay agent tables."""
    # Create relay_agents table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS relay_agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            hardware_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            hostname TEXT,
            ip_address TEXT,
            os_type TEXT,
            os_version TEXT,
            python_version TEXT,
            agent_version TEXT,
            status TEXT DEFAULT 'pending',
            last_seen REAL,
            last_heartbeat REAL,
            created_at REAL NOT NULL,
            activated_at REAL,
            revoked_at REAL,
            config TEXT
        )
    """)

    # Create relay_events table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS relay_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            event_data TEXT,
            ip_address TEXT,
            timestamp REAL NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES relay_agents(agent_id) ON DELETE CASCADE
        )
    """)

    # Create relay_metrics table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS relay_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            metric_type TEXT NOT NULL,
            metric_data TEXT NOT NULL,
            timestamp REAL NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES relay_agents(agent_id) ON DELETE CASCADE
        )
    """)

    # Create relay_flows table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS relay_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            flow_key TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            packets_sent INTEGER DEFAULT 0,
            packets_recv INTEGER DEFAULT 0,
            bytes_sent INTEGER DEFAULT 0,
            bytes_recv INTEGER DEFAULT 0,
            first_seen REAL,
            last_seen REAL,
            dst_country TEXT,
            dst_hostname TEXT,
            FOREIGN KEY (agent_id) REFERENCES relay_agents(agent_id) ON DELETE CASCADE
        )
    """)

    # Create indexes
    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_relay_agents_id ON relay_agents(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relay_agents_hardware ON relay_agents(hardware_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relay_agents_status ON relay_agents(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relay_events_agent ON relay_events(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relay_events_time ON relay_events(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relay_metrics_agent ON relay_metrics(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relay_metrics_time ON relay_metrics(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relay_flows_agent ON relay_flows(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relay_flows_time ON relay_flows(last_seen DESC)")
    except Exception:
        pass


def _migrate_v4_to_v5(conn) -> None:
    """Migration: Add security features (reputation, alerts, blacklist)."""
    # Create reputation_cache table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reputation_cache (
            ip TEXT PRIMARY KEY,
            threat_level TEXT NOT NULL,
            confidence_score INTEGER DEFAULT 0,
            total_reports INTEGER DEFAULT 0,
            last_reported REAL,
            categories TEXT,
            isp TEXT,
            domain TEXT,
            country_code TEXT,
            is_tor INTEGER DEFAULT 0,
            is_vpn INTEGER DEFAULT 0,
            is_proxy INTEGER DEFAULT 0,
            is_datacenter INTEGER DEFAULT 0,
            cached_at REAL NOT NULL,
            expires_at REAL NOT NULL
        )
    """)

    # Create alerts table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            session_id INTEGER,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            port INTEGER,
            protocol TEXT,
            flow_key TEXT,
            details TEXT,
            timestamp REAL NOT NULL,
            acknowledged INTEGER DEFAULT 0,
            acknowledged_at REAL,
            acknowledged_by TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        )
    """)

    # Create ip_blacklist table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_blacklist (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            added_at REAL NOT NULL,
            added_by TEXT,
            expires_at REAL,
            is_active INTEGER DEFAULT 1
        )
    """)

    # Create indexes
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reputation_expires ON reputation_cache(expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reputation_threat ON reputation_cache(threat_level)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id, timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_blacklist_active ON ip_blacklist(is_active)")
    except Exception:
        pass


def cleanup_expired_cache(conn, geo_ttl: float = 86400, dns_ttl: float = 3600) -> int:
    """Remove expired cache entries. Returns count of removed entries."""
    import time
    now = time.time()

    cursor = conn.execute("DELETE FROM geo_cache WHERE expires_at < ?", [now])
    geo_removed = cursor.rowcount

    cursor = conn.execute("DELETE FROM dns_cache WHERE expires_at < ?", [now])
    dns_removed = cursor.rowcount

    conn.commit()
    return geo_removed + dns_removed
