# PacketTracer Architecture

## Overview

PacketTracer is a real-time network packet analysis tool with a terminal-based dashboard. It captures packets using libpcap (via scapy), tracks flows, performs geo-location lookups, resolves hostnames/domains, identifies network ownership, and provides traffic classification and analysis.

## Directory Structure

```
packettracer/
├── main.py                     # CLI entry point
├── run.sh                      # Wrapper script for sudo execution
├── config.py                   # Configuration constants
├── requirements.txt            # Python dependencies
├── architecture.md             # This file
├── packettracer.log            # Runtime debug log (auto-generated)
│
├── db/                         # Database layer (SQLite with WAL)
│   ├── __init__.py
│   ├── connection.py          # ConnectionPool - WAL-enabled connection pool
│   ├── schema.py              # Database schema definitions
│   ├── writer.py              # DatabaseWriter - background batch writer
│   └── repositories/          # Data access layer
│       ├── __init__.py
│       ├── session_repo.py    # Session management
│       ├── flow_repo.py       # Flow data access
│       ├── port_repo.py       # Port statistics
│       ├── geo_repo.py        # Geo cache persistence
│       ├── dns_repo.py        # DNS cache persistence
│       ├── hop_repo.py        # Traceroute/hop data
│       ├── device_repo.py     # Device tracking & classification
│       └── route_repo.py      # Route pattern tracking
│
├── capture/                    # Packet capture layer
│   ├── __init__.py
│   ├── sniffer.py             # PacketSniffer - libpcap wrapper using scapy
│   └── parser.py              # PacketParser - header extraction
│
├── tracking/                   # Flow and traffic tracking
│   ├── __init__.py
│   ├── flow.py                # FlowTracker - 5-tuple flow aggregation
│   ├── db_flow.py             # DBFlowTracker - database-backed flow tracker
│   ├── hops.py                # HopAnalyzer - TTL-based hop estimation
│   ├── path.py                # PathTracer - active traceroute
│   ├── db_path.py             # DBPathTracer - database-backed path tracer
│   ├── classifier.py          # TrafficClassifier - purpose detection
│   ├── ports.py               # PortTracker - port traffic statistics
│   └── db_ports.py            # DBPortTracker - database-backed port tracker
│
├── geo/                        # Geographic and identity resolution
│   ├── __init__.py
│   ├── cache.py               # GeoCache - LRU cache with TTL
│   ├── resolver.py            # GeoResolver - ip-api.com with callbacks
│   ├── dns_resolver.py        # DNSResolver - reverse DNS with callbacks
│   └── ownership.py           # OwnershipResolver - WHOIS/ASN lookups
│
├── dashboard/                  # Terminal UI
│   ├── __init__.py
│   ├── app.py                 # Dashboard - main application
│   ├── input_handler.py       # InputHandler - keyboard input with escape sequences
│   ├── widgets.py             # Reusable Rich components
│   └── panels/                # Dashboard views
│       ├── __init__.py
│       ├── traffic.py         # TrafficPanel - live flow table with hostnames
│       ├── paths.py           # PathsPanel - traceroute with ownership info
│       ├── stats.py           # StatsPanel - aggregate statistics + top domains
│       ├── analysis.py        # AnalysisPanel - packet analysis
│       └── ports.py           # PortsPanel - port traffic view
│
└── utils/                      # Utilities
    ├── __init__.py
    ├── network.py             # Network helper functions
    └── logger.py              # Logging configuration
```

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Dashboard (app.py)                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │
│  │TrafficPanel │ │ PathsPanel  │ │ StatsPanel  │ │AnalysisPanel│ ...    │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘        │
│                         │                                                │
│                    InputHandler (keyboard input)                         │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          ▼                        ▼                        ▼
┌──────────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐
│   Tracking Layer     │  │ Resolution Layer│  │    Database Layer       │
│  ┌────────────────┐  │  │ ┌─────────────┐ │  │  ┌───────────────────┐  │
│  │ DBFlowTracker  │  │  │ │ GeoResolver │ │  │  │  ConnectionPool   │  │
│  └────────────────┘  │  │ └─────────────┘ │  │  │    (WAL mode)     │  │
│  ┌────────────────┐  │  │ ┌─────────────┐ │  │  └───────────────────┘  │
│  │ DBPortTracker  │  │  │ │ DNSResolver │ │  │  ┌───────────────────┐  │
│  └────────────────┘  │  │ └─────────────┘ │  │  │  DatabaseWriter   │  │
│  ┌────────────────┐  │  │ ┌─────────────┐ │  │  │  (batch queue)    │  │
│  │  HopAnalyzer   │  │  │ │ Ownership   │ │  │  └───────────────────┘  │
│  └────────────────┘  │  │ │ Resolver    │ │  │  ┌───────────────────┐  │
│  ┌────────────────┐  │  │ └─────────────┘ │  │  │   Repositories    │  │
│  │PacketAnalyzer  │  │  └─────────────────┘  │  │ Flow/Port/Geo/DNS │  │
│  └────────────────┘  │                       │  │ Session/Hop/Device│  │
└──────────────────────┘                       │  └───────────────────┘  │
          │                                    └─────────────────────────┘
          ▼                                              │
┌─────────────────────────────────────────────────────────────────────────┐
│                           Capture Layer                                  │
│              PacketSniffer ──► PacketParser ──► ParsedPacket            │
│                    │                                                     │
│              libpcap/scapy                                               │
└─────────────────────────────────────────────────────────────────────────┘
          │                                              │
          ▼                                              ▼
    Network Interface                          SQLite Database (WAL)
                                               ~/.packettracer/data.db
```

## Data Flow

1. **Packet Capture**: `PacketSniffer` captures raw packets from the network interface using scapy's `sniff()` function in a background thread.

2. **Packet Parsing**: `PacketParser.parse()` extracts relevant headers into a `ParsedPacket` dataclass:
   - Ethernet: MAC addresses
   - IP: Source/dest IP, TTL, protocol
   - TCP/UDP: Ports, flags, sequence numbers
   - ICMP: Type and code

3. **Flow Tracking**: `FlowTracker` aggregates packets into bidirectional flows using a 5-tuple key (src_ip, dst_ip, src_port, dst_port, protocol). Each `Flow` tracks:
   - Byte/packet counts (sent/received)
   - TTL values for hop estimation
   - First/last seen timestamps
   - Geo information (when resolved)
   - Unique `flow_key` property for persistent identification

4. **Analysis Pipeline**: Each packet triggers:
   - `HopAnalyzer.record_ttl()` - TTL-based hop tracking
   - `PacketAnalyzer.process_packet()` - Protocol/size/flag analysis
   - `TrafficClassifier.classify_flow()` - Purpose detection
   - `PortTracker.record_packet()` - Port statistics, hit counts, scan detection

5. **Resolution Pipeline** (async): For non-private IPs:
   - `GeoResolver.resolve_async()` - Country, city, ISP via ip-api.com
   - `DNSResolver.resolve_async()` - Reverse DNS hostname/domain lookup
   - `OwnershipResolver` - WHOIS/ASN information (on-demand)

## Key Classes

### Capture Layer

#### `PacketSniffer`
- Wraps scapy's packet capture
- Runs in background thread
- Supports BPF filters
- Callback-based packet delivery

#### `PacketParser`
- Stateless packet header extraction
- Returns `ParsedPacket` dataclass
- Handles IP, TCP, UDP, ICMP

### Tracking Layer

#### `FlowTracker`
- Thread-safe flow table (OrderedDict)
- LRU eviction when over capacity
- Normalizes bidirectional flows to single key
- Provides sorted/filtered flow lists

#### `PortTracker`
- Tracks traffic statistics per port
- Time-series history (last 60 seconds)
- Service name mapping
- Unique source/destination counting
- **Hit count tracking** - unique source IPs per port
- **Port scan detection**:
  - Tracks ports hit by each source IP within time window
  - `ScanActivity` dataclass with scan rate calculation
  - Heuristic detection: >10 ports at >0.5 ports/sec = likely scanner
  - `get_scan_activity()` and `get_likely_scanners()` methods

#### `TrafficClassifier`
- Heuristic traffic classification
- Port-based service detection
- Pattern detection (streaming, VoIP, handshake)
- Encryption detection
- `classify_flow()` - classifies and stores result
- `get_classification(flow)` - retrieves stored classification by flow

#### `PacketAnalyzer`
- Protocol distribution
- Packet size distribution
- TCP flag analysis
- ICMP type tracking
- Throughput calculation

### Resolution Layer

#### `GeoResolver`
- ip-api.com integration
- Rate limiting (45 req/min)
- Background batch processing
- LRU cache with TTL

#### `DNSResolver`
- Reverse DNS (PTR) lookups
- Background async resolution
- **FQDN tracking** - stores full qualified domain name
- Domain extraction from FQDN (base domain like "example.com")
- Short hostname extraction (first label of FQDN)
- LRU cache with configurable TTL
- `HostInfo` dataclass with `fqdn`, `hostname`, `domain`, `display_name`

#### `OwnershipResolver`
- WHOIS queries to regional registries
- ASN/organization lookup
- Referral server support (ARIN, RIPE, APNIC, etc.)
- `OwnershipInfo` dataclass with asn, as_name, org, isp, network

### Dashboard Layer

#### `Dashboard`
- Main application controller
- Manages all panels and services
- Input event routing
- Lifecycle management
- Passes resolvers to panels for hostname/ownership display

#### `InputHandler`
- Terminal cbreak mode for immediate input
- Arrow key/escape sequence parsing with 100ms timeout
- Uses `select()` for non-blocking input checks
- Supports special keys: arrows, page up/down, home/end, enter, space, escape

#### Panels

##### TrafficPanel (View 1)
- Live flow table with navigation/selection
- Columns: Source, Destination, **FQDN**, Proto, Sent, Recv, Pkts, Location
- **FQDN resolution** for destination IPs (full qualified domain name)
- **Destinations view** (`g` key) - aggregates connections by destination
- Keyboard navigation with cursor and selection
- **Persistent selection**: Uses `flow_key` (5-tuple) instead of list indices
  - Selection survives list reordering when new traffic arrives
  - Selection persists across all view switches
  - Selected flows passed to other panels for filtering

##### PathsPanel (View 2)
- Traceroute results with **FQDN** and **owner/ASN**
- Columns: Hop, IP, **FQDN**, RTT, Location, Owner/ASN
- **Database-backed traceroutes** - persisted via `DBPathTracer`
- **Route pattern tracking** - detects and displays route changes
- **Route history** - shows historical routes to destinations
- Hop summary table with FQDN and ownership info
- DNS resolution for each hop
- Ownership lookup showing AS name and number
- Respects flow selection from Traffic view (filters hop summary to selected IPs)

##### StatsPanel (View 3)
- Country/ISP/protocol breakdown
- Top Talkers with hostname display
- **Top Domains** panel showing traffic by domain
- Overview with cache statistics
- Respects flow selection from Traffic view for filtering

##### AnalysisPanel (View 4)
- Traffic classification and encryption status
- Protocol distribution
- Packet size analysis
- TCP flag breakdown
- Respects flow selection from Traffic view for filtering

##### PortsPanel (View 5)
- Port traffic table with **Hits** column (unique source IPs hitting each port)
- Traffic by port range (well-known, registered, dynamic)
- Service-based traffic aggregation
- **Port Scan Detection** panel:
  - Shows likely port scanners (red warning)
  - Suspicious activity (5+ ports hit)
  - Scan rate calculation
- **Top Hit Ports** panel with bar chart
- Respects flow selection from Traffic view for filtering
- Summary with real-time scan alert status

### Database Layer

The database layer provides persistent storage using SQLite with WAL (Write-Ahead Logging) mode for concurrent access.

#### `ConnectionPool`
- WAL mode enables concurrent reads during writes
- Single write connection with exclusive lock
- Multiple read connections (default: 4) for parallel queries
- Automatic schema initialization on startup
- Connection lifecycle management

#### `DatabaseWriter`
- Background thread for non-blocking writes
- Batches operations (100 ops or 100ms flush interval)
- Queue-based write requests
- Transaction batching for efficiency
- Graceful shutdown with flush

#### Repositories

| Repository | Purpose |
|------------|---------|
| `SessionRepository` | Capture session lifecycle, stats aggregation |
| `FlowRepository` | Flow CRUD, geo/DNS updates, filtering/sorting |
| `PortRepository` | Port statistics, service breakdown |
| `GeoRepository` | Persistent geo cache (24h TTL) |
| `DNSRepository` | Persistent DNS cache (1h TTL) |
| `HopRepository` | Traceroute data, latency samples |
| `DeviceRepository` | Device classification, ownership info |
| `RouteRepository` | Route pattern tracking, change detection |

#### Database Schema (18 tables, v2)
- `sessions` - Capture session metadata
- `flows` - Flow data with denormalized geo/DNS/classification
  - Includes `src_fqdn`, `dst_fqdn` for full qualified domain names
- `port_stats` - Per-port traffic statistics
- `geo_cache` - Persistent geo cache (24h TTL)
- `dns_cache` - Persistent DNS cache with `fqdn` field (1h TTL)
- `traceroutes` / `hops` / `latency_samples` - Path tracing data
- `path_summary` - Aggregated path statistics
- `devices` / `node_ownership` - Device and network ownership
- `route_patterns` / `route_changes` - Route tracking
- `scan_activity` / `classifications` - Security analysis
- `ns_lookup` - NS record cache
- `schema_version` - Migration tracking (current: v2)

### Utilities

#### `logger.py`
- File-based logging to `packettracer.log`
- Debug-level logging for troubleshooting
- Avoids stdout to prevent Rich conflicts
- `log_exception()` helper for full tracebacks

## Threading Model

```
Main Thread
    │
    ├── Dashboard loop (50ms cycle)
    │   ├── Read input events (select-based, non-blocking)
    │   ├── Process key events
    │   ├── Update UI panels (read from database)
    │   └── Sleep
    │
    └── Background Threads:
        ├── PacketSniffer thread (continuous capture)
        │   └── Queues writes to DatabaseWriter
        ├── GeoResolver thread (batch API calls)
        │   └── Persists results to geo_cache table
        ├── DNSResolver thread (PTR lookups)
        │   └── Persists results to dns_cache table
        └── DatabaseWriter thread (batch writes)
            └── Flushes every 100 ops or 100ms
```

### Database Concurrency

SQLite WAL mode enables:
- **Readers never block**: UI can query while capture writes
- **Writer batching**: Groups writes into transactions
- **Consistent snapshots**: Each read sees a consistent state
- **No lock contention**: Eliminates UI lag from capture thread

## Configuration (config.py)

### Dashboard Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `REFRESH_RATE` | 0.1s | Dashboard update interval |
| `MAX_FLOWS_DISPLAY` | 50 | Max flows in traffic panel |

### Resolution Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `GEO_API_RATE_LIMIT` | 45/min | ip-api.com rate limit |
| `GEO_CACHE_SIZE` | 10000 | In-memory geo cache entries |
| `GEO_CACHE_TTL` | 3600s | In-memory geo cache expiry |
| `DNS_CACHE_SIZE` | 5000 | In-memory DNS cache entries |
| `DNS_CACHE_TTL` | 3600s | In-memory DNS cache expiry |
| `DNS_TIMEOUT` | 1s | DNS lookup timeout |

### Flow Tracking Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `FLOW_TIMEOUT` | 300s | Flow idle timeout |
| `MAX_FLOWS` | 50000 | Max tracked flows |

### Database Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `DB_PATH` | ~/.packettracer/data.db | Database file location |
| `DB_READ_POOL_SIZE` | 4 | Number of read connections |
| `DB_WRITE_BATCH_SIZE` | 100 | Batch size for writes |
| `DB_WRITE_FLUSH_MS` | 100 | Flush interval in milliseconds |
| `DB_WAL_MODE` | True | Use WAL mode for concurrent access |
| `DB_GEO_CACHE_TTL` | 86400s | Persistent geo cache TTL (24h) |
| `DB_DNS_CACHE_TTL` | 3600s | Persistent DNS cache TTL (1h) |
| `DB_SESSION_RETENTION_DAYS` | 30 | Keep sessions for N days |

## Keyboard Controls

### Global
| Key | Action |
|-----|--------|
| `1-5` | Switch views |
| `p` | Pause/resume capture |
| `t` | Start traceroute |
| `q` | Quit |

### Traffic View (1)
| Key | Action |
|-----|--------|
| `↑/↓` | Navigate flows |
| `PgUp/PgDn` | Page navigation |
| `Home/End` | Jump to start/end |
| `Space` | Select/deselect flow |
| `Enter` | Traceroute to destination |
| `/` | Filter by IP substring |
| `:` | Filter by port number |
| `f` | Cycle protocol filter (All/TCP/UDP/ICMP) |
| `s` | Cycle sort mode (bytes/packets/time) |
| `g` | Toggle flows/destinations view |
| `l` | Toggle local traffic visibility |
| `a` | Select all flows |
| `c` | Clear filters and selection |

### Paths View (2)
| Key | Action |
|-----|--------|
| `s` | Trace selected flow destinations |
| `r` | Refresh traces |
| `c` | Clear traces |

### Ports View (5)
| Key | Action |
|-----|--------|
| `s` | Cycle sort mode (bytes/packets/connections/rate) |

## Dependencies

- **scapy**: Packet capture and parsing
- **rich**: Terminal UI rendering
- **requests**: HTTP for geo API

## Running

```bash
# Install dependencies
pip install -r requirements.txt

# Run (requires root for packet capture)
sudo .venv/bin/python main.py

# Or use the wrapper script
./run.sh

# With options
./run.sh -i eth0              # Specific interface
./run.sh -f "tcp port 443"    # BPF filter
./run.sh -t 8.8.8.8           # Start with traceroute
./run.sh --list               # List interfaces
./run.sh --simple             # Run without keyboard input
```

## Debugging

Debug logs are written to `packettracer.log` in the project directory:

```bash
# View logs in real-time
tail -f packettracer.log

# Check for errors
grep ERROR packettracer.log
```

## Future Enhancements

- [ ] Packet payload inspection (with privacy controls)
- [ ] Export to PCAP/JSON/CSV
- [ ] Alert rules and notifications
- [ ] Remote capture support
- [ ] Protocol-specific decoders (HTTP, DNS, TLS)
- [ ] Bandwidth graphs and time-series visualization
- [ ] IPv6 support improvements
- [ ] Web-based dashboard option
- [ ] SNMP integration for network device monitoring
- [ ] NetFlow/sFlow/IPFIX collector mode
- [ ] Anomaly detection with baseline learning
- [ ] Integration with threat intelligence feeds
- [ ] Real-time alerting (email, webhook, syslog)
- [ ] Multi-interface capture aggregation
- [ ] PCAP file import/replay
- [ ] API for external integrations

## Recently Implemented

### FQDN & Path Tracking (v0.3)
- [x] **FQDN tracking** - stores full qualified domain name (e.g., "server1.us-west-2.compute.amazonaws.com")
- [x] **DBPathTracer** - database-backed traceroute with persistence
- [x] **Route pattern persistence** - traceroutes stored in database
- [x] **Route history display** - view historical routes to destinations
- [x] **Route change detection** - track and display route changes
- [x] **Schema v2 migration** - added `fqdn` columns to flows and dns_cache tables
- [x] **Destinations view** - aggregate connections by destination (`g` key)
- [x] **FQDN display in panels** - Traffic and Paths panels show full FQDN

### Database & Persistence (v0.2)
- [x] **SQLite database with WAL mode** - concurrent reads during writes
- [x] **Historical data persistence** - sessions, flows, port stats survive restarts
- [x] **Background batch writer** - non-blocking database writes (100 ops/100ms)
- [x] **Persistent geo/DNS cache** - 24h geo cache, 1h DNS cache in database
- [x] **Session management** - track capture sessions with timestamps and stats
- [x] **Device tracking schema** - classify endpoints, routers, switches
- [x] **Route pattern tracking** - detect and log route changes
- [x] **Callback-based resolution** - geo/DNS data properly attaches to flows

### Traffic Analysis (v0.1)
- [x] Port scan detection with heuristic analysis
- [x] Hit count metrics (unique sources per port)
- [x] Flow selection filtering across all views (Paths/Stats/Analysis/Ports)
- [x] **Persistent flow selection** - selection by `flow_key` survives list reordering
- [x] Hostname/domain resolution in all panels
- [x] Ownership/ASN display in traceroute
- [x] API traffic filtering (prevents ip-api.com self-capture)
- [x] TrafficClassifier.get_classification() for retrieving stored classifications
