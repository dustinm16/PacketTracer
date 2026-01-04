# PacketTracer Roadmap

## Recently Completed (v0.3)

### FQDN & Path Tracking
- **FQDN tracking** - Full qualified domain names stored for all resolved IPs
  - `HostInfo` and `DNSRecord` now include `fqdn`, `hostname`, `domain` fields
  - Flows store `src_fqdn` and `dst_fqdn`
  - Panels display full FQDN instead of shortened domain
- **DBPathTracer** - Database-backed traceroute with persistence
  - Wraps PathTracer and persists to HopRepository
  - Route patterns stored in RouteRepository
  - Route change detection and display
- **Panel repository migration** - All panels now use database repositories
  - TrafficPanel → DBFlowTracker
  - PortsPanel → DBPortTracker
  - PathsPanel → DBPathTracer + HopRepository + RouteRepository
- **Schema v2** - Migration adds `fqdn` columns to existing databases

### UI Improvements
- **Destinations view** - Toggle with `g` key to aggregate by destination
- **Route history panel** - Shows historical routes to destinations
- **Route changes panel** - Displays route changes (new, +hop, -hop, reroute)

---

## Industry Comparison Analysis

### Reference Tools Analyzed
- **Wireshark** - Packet analysis gold standard
- **ntopng** - Network traffic monitoring and flow analysis
- **Zeek (Bro)** - Network security monitoring framework
- **tcpdump** - Command-line packet capture
- **Suricata/Snort** - IDS/IPS engines
- **Nagios/Zabbix** - Infrastructure monitoring
- **SolarWinds/PRTG** - Enterprise network monitoring

---

## Feature Gap Analysis

### Legend
- ✅ Implemented
- 🔄 Partial/In Progress
- ❌ Not Implemented
- 🎯 Priority Target

### 1. Packet Capture & Parsing

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| Live capture (libpcap) | ✅ | ✅ |
| BPF filtering | ✅ | ✅ |
| Multi-interface capture | ❌ | ✅ |
| PCAP file read/write | ❌ 🎯 | ✅ |
| Remote capture (rpcapd) | ❌ | ✅ |
| Ring buffer capture | ❌ | ✅ |
| Capture statistics | ✅ | ✅ |

### 2. Protocol Decoding

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| Ethernet/IP/TCP/UDP/ICMP | ✅ | ✅ |
| HTTP/HTTPS detection | 🔄 (port-based) | ✅ (deep inspection) |
| DNS parsing | ❌ 🎯 | ✅ |
| TLS/SSL analysis | ❌ 🎯 | ✅ |
| DHCP/ARP | ❌ | ✅ |
| Custom protocol plugins | ❌ | ✅ |
| Protocol hierarchy stats | ❌ | ✅ |

### 3. Flow Analysis

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| 5-tuple flow tracking | ✅ | ✅ |
| Bidirectional flows | ✅ | ✅ |
| Flow timeout/expiry | ✅ | ✅ |
| NetFlow/sFlow/IPFIX | ❌ 🎯 | ✅ |
| Flow export | ❌ | ✅ |
| Application detection | 🔄 (heuristic) | ✅ (DPI/nDPI) |
| Conversation tracking | ✅ | ✅ |

### 4. Security Analysis

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| Port scan detection | ✅ | ✅ |
| Geo-blocking awareness | ✅ | ✅ |
| ASN/ownership lookup | ✅ | ✅ |
| Signature-based IDS | ❌ 🎯 | ✅ |
| Anomaly detection | ❌ 🎯 | ✅ |
| Threat intelligence | ❌ 🎯 | ✅ |
| SSL/TLS inspection | ❌ | ✅ |
| Malware detection | ❌ | ✅ |
| File extraction | ❌ | ✅ |

### 5. Performance Monitoring

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| Throughput calculation | ✅ | ✅ |
| Latency measurement | 🔄 (traceroute) | ✅ |
| Packet loss detection | ❌ 🎯 | ✅ |
| Retransmission tracking | ❌ 🎯 | ✅ |
| RTT calculation | 🔄 | ✅ |
| Jitter measurement | ❌ | ✅ |
| QoS/DSCP analysis | ❌ | ✅ |
| Baseline comparison | ❌ 🎯 | ✅ |

### 6. Visualization

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| Terminal UI | ✅ | 🔄 |
| Real-time updates | ✅ | ✅ |
| Traffic graphs | ❌ 🎯 | ✅ |
| Network topology | ❌ 🎯 | ✅ |
| Geographic maps | ❌ | ✅ |
| Time-series charts | ❌ 🎯 | ✅ |
| Web dashboard | ❌ | ✅ |
| Custom dashboards | ❌ | ✅ |

### 7. Alerting & Notifications

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| In-app alerts | ✅ (scan detection) | ✅ |
| Threshold alerts | ❌ 🎯 | ✅ |
| Email notifications | ❌ | ✅ |
| Webhook integration | ❌ | ✅ |
| Syslog export | ❌ 🎯 | ✅ |
| SNMP traps | ❌ | ✅ |
| Alert rules engine | ❌ 🎯 | ✅ |

### 8. Data Management

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| SQLite persistence | ✅ | 🔄 |
| Session history | ✅ | ✅ |
| Data retention | ✅ | ✅ |
| Export CSV/JSON | ❌ 🎯 | ✅ |
| Export PCAP | ❌ 🎯 | ✅ |
| Database scaling | ❌ | ✅ (PostgreSQL/etc) |
| Data compression | ❌ | ✅ |

### 9. Integration

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| REST API | ❌ 🎯 | ✅ |
| CLI interface | ✅ | ✅ |
| SNMP polling | ❌ | ✅ |
| Syslog ingestion | ❌ | ✅ |
| Elasticsearch | ❌ | ✅ |
| Grafana dashboards | ❌ | ✅ |
| Prometheus metrics | ❌ | ✅ |

### 10. Reporting

| Feature | PacketTracer | Industry Standard |
|---------|--------------|-------------------|
| Real-time stats | ✅ | ✅ |
| Session reports | ❌ 🎯 | ✅ |
| PDF export | ❌ | ✅ |
| Scheduled reports | ❌ | ✅ |
| Custom templates | ❌ | ✅ |

---

## Implementation Phases

### Phase 1: Core Improvements (Priority: High)
**Focus: Complete database integration, essential exports, basic protocol decoding**

#### 1.1 Complete Database Integration
- [x] Update all panels to query from repositories ✅
- [x] DBPathTracer for traceroute persistence ✅
- [x] FQDN tracking in flows and DNS cache ✅
- [x] Route pattern and change tracking ✅
- [ ] Implement historical session viewer (--history flag)
- [ ] Add session comparison feature
- [ ] Cache cleanup and maintenance routines

#### 1.2 Export Capabilities
- [ ] CSV export for flows, ports, sessions
- [ ] JSON export with configurable schema
- [ ] PCAP export from captured data
- [ ] PCAP file import and replay

#### 1.3 Protocol Decoding - DNS
- [ ] DNS query/response parsing
- [ ] DNS transaction tracking
- [ ] Query type statistics (A, AAAA, MX, etc.)
- [ ] DNS-based threat detection (DGA, tunneling)

#### 1.4 TCP Analysis
- [ ] Retransmission detection and counting
- [ ] RTT calculation from SYN/ACK
- [ ] Connection state tracking (handshake, established, teardown)
- [ ] Window size analysis

### Phase 2: Security Features (Priority: High)
**Focus: Threat detection, alerting, security analysis**

#### 2.1 Alert Rules Engine
- [ ] Rule definition format (YAML/JSON)
- [ ] Threshold-based triggers
- [ ] Pattern matching conditions
- [ ] Rate-based detection
- [ ] Alert state management (active/acknowledged/resolved)

#### 2.2 Alerting Destinations
- [ ] Syslog output (RFC 5424)
- [ ] Webhook notifications
- [ ] Email alerts (SMTP)
- [ ] Desktop notifications
- [ ] Alert log file

#### 2.3 Threat Intelligence Integration
- [ ] IP reputation lookup
- [ ] Domain blocklist checking
- [ ] ASN reputation
- [ ] IOC matching (IPs, domains, hashes)
- [ ] Configurable threat feeds

#### 2.4 Anomaly Detection
- [ ] Baseline learning (traffic patterns)
- [ ] Statistical deviation alerts
- [ ] New host/service detection
- [ ] Traffic volume anomalies
- [ ] Time-of-day patterns

### Phase 3: Visualization & Reporting (Priority: Medium)
**Focus: Graphs, charts, time-series, reports**

#### 3.1 Terminal Graphs
- [ ] ASCII bandwidth graphs (sparklines)
- [ ] Traffic over time (last 5m, 1h, 24h)
- [ ] Protocol distribution pie chart
- [ ] Top talkers bar chart

#### 3.2 Time-Series Data
- [ ] Per-second/minute aggregation tables
- [ ] Rollup for historical data
- [ ] Efficient storage for long-term trends

#### 3.3 Session Reports
- [ ] Summary report generation
- [ ] Top statistics compilation
- [ ] Markdown/HTML output
- [ ] Comparison reports (session vs session)

### Phase 4: Protocol Deep Inspection (Priority: Medium)
**Focus: Application-layer visibility**

#### 4.1 HTTP Analysis
- [ ] Request/response parsing
- [ ] URL extraction
- [ ] User-agent tracking
- [ ] Response code statistics
- [ ] Content-type analysis

#### 4.2 TLS/SSL Analysis
- [ ] Handshake parsing
- [ ] Certificate extraction
- [ ] Cipher suite detection
- [ ] JA3/JA3S fingerprinting
- [ ] Certificate validation

#### 4.3 DHCP/ARP
- [ ] DHCP lease tracking
- [ ] ARP table building
- [ ] ARP spoofing detection
- [ ] DHCP starvation detection

### Phase 5: Advanced Features (Priority: Low)
**Focus: Enterprise features, integrations**

#### 5.1 NetFlow/sFlow Collector
- [ ] NetFlow v5/v9 receiver
- [ ] sFlow receiver
- [ ] IPFIX receiver
- [ ] Flow aggregation

#### 5.2 REST API
- [ ] Read-only API for flows/stats
- [ ] WebSocket for live updates
- [ ] Authentication
- [ ] Rate limiting

#### 5.3 Web Dashboard (Optional)
- [ ] Simple web UI alternative
- [ ] Real-time WebSocket updates
- [ ] Mobile-responsive design

#### 5.4 Multi-Interface Support
- [ ] Capture from multiple interfaces
- [ ] Interface aggregation
- [ ] Per-interface statistics
- [ ] VLAN awareness

---

## Quick Wins (Can implement quickly)

1. **CSV Export** - Simple, high value
2. **DNS Query Parsing** - Adds visibility
3. **Retransmission Counter** - TCP health insight
4. **ASCII Sparklines** - Better visualization
5. **Syslog Output** - Integration capability
6. **Session Summary Report** - Useful for reviews

---

## Technical Debt

1. ~~**Panel Repository Migration** - Panels still use trackers directly~~ ✅ Mostly complete
   - TrafficPanel uses DBFlowTracker ✅
   - PortsPanel uses DBPortTracker ✅
   - PathsPanel uses DBPathTracer + HopRepository ✅
   - StatsPanel uses flow_tracker.get_flows() ✅
   - AnalysisPanel derives from selected flows ✅
2. **Test Coverage** - Need unit and integration tests
3. **Error Handling** - More graceful degradation
4. **Documentation** - API docs, user guide
5. **Configuration File** - Move from config.py to YAML

---

## Recommended Implementation Order

### Sprint 1 (Foundation)
1. ~~Complete panel repository migration~~ ✅ Done
2. Implement CSV export
3. Add basic DNS parsing
4. Add retransmission detection

### Sprint 2 (Security)
1. Alert rules engine (basic)
2. Syslog output
3. IP reputation lookup
4. Threshold alerts

### Sprint 3 (Visualization)
1. ASCII time-series graphs
2. Session summary reports
3. Traffic baseline storage
4. Anomaly detection basics

### Sprint 4 (Protocol)
1. Full HTTP parsing
2. TLS fingerprinting
3. Certificate analysis
4. Enhanced classification

### Sprint 5 (Integration)
1. REST API (read-only)
2. Webhook alerts
3. PCAP import/export
4. NetFlow collector

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Protocol coverage | 4 (IP/TCP/UDP/ICMP) | 10+ |
| Export formats | 0 | 4 (CSV, JSON, PCAP, report) |
| Alert channels | 1 (in-app) | 4+ |
| API endpoints | 0 | 10+ |
| Test coverage | 0% | 80%+ |

---

## Resource Estimates

| Phase | Complexity | Effort |
|-------|------------|--------|
| Phase 1 | Medium | Moderate |
| Phase 2 | High | Significant |
| Phase 3 | Medium | Moderate |
| Phase 4 | High | Significant |
| Phase 5 | High | Large |
