# CLAUDE.md — PacketTracer

## Project Overview

PacketTracer is a real-time network packet analysis tool with a terminal-based dashboard. It captures live network traffic using scapy/libpcap, tracks flows, resolves geographic and DNS information, performs security analysis, and renders everything in a Rich-powered terminal UI. Written entirely in Python 3.8+.

## Quick Reference

```bash
# Install dependencies
python -m venv .venv && .venv/bin/pip install -r requirements.txt

# Run (requires root for packet capture)
sudo .venv/bin/python main.py
# or use the wrapper:
./run.sh

# Run tests
pytest                          # all tests
pytest tests/test_flow.py -v    # specific module
pytest -m "not slow"            # skip slow tests
pytest -m "not requires_root"   # skip root-requiring tests
```

## Repository Structure

```
PacketTracer/
├── main.py                 # CLI entry point (argparse)
├── config.py               # All configuration constants (single source of truth)
├── run.sh                  # Sudo wrapper for venv execution
├── requirements.txt        # pip dependencies (scapy, rich, requests, cachetools)
├── pytest.ini              # Test configuration and markers
│
├── capture/                # Packet capture layer
│   ├── sniffer.py          #   PacketSniffer — libpcap wrapper via scapy
│   └── parser.py           #   PacketParser — header extraction, ParsedPacket dataclass
│
├── tracking/               # Flow analysis and classification
│   ├── flow.py             #   FlowTracker — bidirectional 5-tuple aggregation
│   ├── db_flow.py          #   DBFlowTracker — database-backed variant
│   ├── classifier.py       #   TrafficClassifier — 18 traffic categories
│   ├── ports.py            #   PortTracker — port statistics, scan detection
│   ├── db_ports.py         #   DBPortTracker — persistent port tracking
│   ├── hops.py             #   HopAnalyzer — TTL-based hop estimation
│   ├── path.py             #   PathTracer — active traceroute
│   ├── db_path.py          #   DBPathTracer — persistent traceroute
│   ├── dns_tracker.py      #   DNS query tracking
│   └── tcp_state.py        #   TCP state machine
│
├── geo/                    # Geographic and network resolution
│   ├── cache.py            #   GeoCache — LRU with TTL
│   ├── resolver.py         #   GeoResolver — ip-api.com integration
│   ├── dns_resolver.py     #   DNSResolver — reverse DNS + FQDN extraction
│   └── ownership.py        #   OwnershipResolver — WHOIS/ASN lookups
│
├── db/                     # Database persistence (SQLite with WAL)
│   ├── connection.py       #   ConnectionPool — thread-safe WAL connection pool
│   ├── schema.py           #   18 table definitions
│   ├── writer.py           #   DatabaseWriter — background batch writer
│   └── repositories/       #   Repository pattern data access (11 repos)
│       ├── session_repo.py
│       ├── flow_repo.py
│       ├── port_repo.py
│       ├── geo_repo.py
│       ├── dns_repo.py
│       ├── dns_query_repo.py
│       ├── hop_repo.py
│       ├── device_repo.py
│       ├── route_repo.py
│       └── relay_repo.py
│
├── dashboard/              # Terminal UI (Rich library)
│   ├── app.py              #   Dashboard main controller
│   ├── input_handler.py    #   Keyboard input with escape sequences
│   ├── widgets.py          #   Reusable Rich components
│   ├── graphs.py           #   ASCII visualization
│   └── panels/             #   Dashboard views (10+ panels)
│       ├── traffic.py      #     Live flow table
│       ├── paths.py        #     Traceroute results
│       ├── stats.py        #     Aggregate statistics
│       ├── analysis.py     #     Traffic classification
│       ├── ports.py        #     Port statistics
│       ├── dns.py          #     DNS analysis
│       ├── dpi.py          #     Deep packet inspection
│       ├── alerts.py       #     Security alerts
│       ├── relay.py        #     Relay agent status
│       ├── tcp.py          #     TCP analysis
│       └── trends.py       #     Traffic trends
│
├── security/               # Security analysis
│   ├── alerts.py           #   AlertEngine — multi-destination alerting
│   ├── destinations.py     #   Syslog, webhook, email destinations
│   ├── reputation.py       #   IP reputation via AbuseIPDB
│   └── graph.py            #   Connection topology graph
│
├── analysis/               # Deep packet inspection
│   └── dpi.py              #   OS fingerprinting, anomaly scoring
│
├── export/                 # Data export
│   ├── base.py             #   Exporter base class
│   ├── csv_exporter.py     #   CSV export
│   └── json_exporter.py    #   JSON export
│
├── relay/                  # Distributed capture agents
│   ├── agent/agent.py      #   Remote capture agent
│   ├── server/relay_server.py  # Relay server (WebSocket)
│   ├── server/protocol.py  #   Relay protocol
│   └── deploy/deployer.py  #   Agent deployment
│
├── utils/                  # Helpers
│   ├── logger.py           #   File-based logging
│   ├── network.py          #   Network helper functions
│   └── validation.py       #   Data validation
│
└── tests/                  # Test suite
    ├── conftest.py         #   Shared fixtures (mock packets, flows, DB, caches)
    ├── test_cache.py
    ├── test_classifier.py
    ├── test_connection.py
    ├── test_dpi.py
    ├── test_flow.py
    ├── test_parser.py
    ├── test_ports.py
    ├── test_security.py
    ├── test_sniffer.py
    └── test_utils.py
```

## Architecture

The codebase follows a layered pipeline:

1. **Capture** — `capture/sniffer.py` sniffs packets via scapy, `parser.py` extracts headers into `ParsedPacket` dataclasses.
2. **Tracking** — `tracking/flow.py` aggregates packets into bidirectional flows keyed by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol). Classifiers, port trackers, and TCP state machines enrich flow data.
3. **Resolution** — `geo/resolver.py` looks up GeoIP via ip-api.com (rate-limited to 45 req/min). `dns_resolver.py` does reverse DNS. `ownership.py` does WHOIS/ASN. All use LRU caches with TTL.
4. **Database** — SQLite with WAL mode via `db/connection.py` (thread-safe pool). `db/writer.py` does non-blocking background batch writes. 11 repositories implement the data access layer.
5. **Security** — Alert engine with port scan detection, IP reputation checks, connection graph analysis.
6. **Dashboard** — `dashboard/app.py` drives a Rich terminal UI. 10+ panels in `dashboard/panels/` render different views. Keyboard navigation via `input_handler.py`.
7. **Export** — CSV and JSON exporters in `export/`.

**Threading model:** The sniffer runs in a background thread. The database writer runs in its own thread. Geo/DNS resolution use callback-based async patterns. The dashboard refresh loop runs on the main thread.

## Dependencies

| Package | Purpose |
|---------|---------|
| `scapy>=2.5.0` | Packet capture and parsing (libpcap) |
| `rich>=13.0.0` | Terminal UI rendering |
| `requests>=2.31.0` | HTTP API calls (GeoIP, reputation) |
| `cachetools>=5.3.0` | LRU caching with TTL |

SQLite3 is from the Python standard library. No compiled extensions.

## Testing

- **Framework:** pytest with verbose output and short tracebacks (configured in `pytest.ini`)
- **Fixtures:** Shared in `tests/conftest.py` — mock packets (`mock_tcp_packet`, `mock_udp_packet`, `mock_icmp_packet`), parsed packets, sample flows, temp DB paths, connection pools, caches, classifiers, port trackers
- **Markers:**
  - `@pytest.mark.slow` — long-running tests
  - `@pytest.mark.integration` — integration tests
  - `@pytest.mark.requires_network` — needs network access
  - `@pytest.mark.requires_root` — needs root privileges
- **Integration test:** `test_db_integration.py` at root tests database write pipeline

Run all tests: `pytest`
Run excluding slow: `pytest -m "not slow"`

## Configuration

All configuration is centralized in `config.py` as module-level constants. Key groups:

- **Capture:** `DEFAULT_INTERFACE`, `CAPTURE_FILTER`, `SNAP_LENGTH`
- **Geo API:** `GEO_API_URL`, `GEO_API_RATE_LIMIT` (45/min), `GEO_CACHE_SIZE` (10k), `GEO_CACHE_TTL` (1h)
- **Dashboard:** `REFRESH_RATE` (100ms), `MAX_FLOWS_DISPLAY` (50)
- **DNS:** `DNS_CACHE_SIZE` (5k), `DNS_CACHE_TTL` (1h), `DNS_TIMEOUT` (1s)
- **Flows:** `FLOW_TIMEOUT` (300s), `MAX_FLOWS` (50k)
- **Database:** `DB_PATH` (~/.packettracer/data.db), `DB_WAL_MODE` (True), `DB_READ_POOL_SIZE` (4), `DB_WRITE_BATCH_SIZE` (100)
- **Security:** `ALERTS_PORT_SCAN_THRESHOLD` (10 ports), `REPUTATION_API_KEY` (AbuseIPDB)
- **Relay:** `RELAY_SERVER_PORT` (8765), heartbeat/metrics intervals

## Code Conventions

- **Python 3.8+** — uses dataclasses, f-strings, type hints, pathlib
- **No build system** — pure Python, run directly with `python main.py`
- **Imports:** Standard library first, then third-party, then local modules. `sys.path` manipulation at entry points (`main.py`, `conftest.py`)
- **Classes:** PascalCase. Core classes use composition (Dashboard holds Sniffer, FlowTracker, GeoResolver, etc.)
- **Data classes:** `ParsedPacket` and `Flow` are dataclasses
- **Database pattern:** Repository classes in `db/repositories/` encapsulate SQL queries. `ConnectionPool` manages thread-safe access. `DatabaseWriter` handles async batch writes.
- **Caching:** `GeoCache` and DNS caches use `cachetools.TTLCache` or custom LRU implementations
- **Error handling:** Broad try/except at top-level entry points. Internal modules raise or log specific exceptions.
- **Logging:** `utils/logger.py` writes to file (not stdout, to avoid interfering with the Rich dashboard)
- **Root required:** Packet capture requires `sudo`. The `check_permissions()` function in `main.py` enforces `euid == 0`.

## CLI Usage

```
sudo python main.py                    # Auto-detect interface
sudo python main.py -i eth0            # Specific interface
sudo python main.py -f "tcp port 80"   # BPF filter
sudo python main.py --list             # List interfaces
sudo python main.py -t 8.8.8.8         # Traceroute on start
sudo python main.py --no-geo           # Disable geo lookups
sudo python main.py --simple           # No keyboard input (Ctrl+C to exit)
```

## Common Tasks for AI Assistants

**Adding a new dashboard panel:**
1. Create `dashboard/panels/your_panel.py` with a render function returning a Rich `Table` or `Panel`
2. Register it in `dashboard/app.py` — add a view number, keyboard binding, and call the render function in the refresh loop

**Adding a new database table:**
1. Define the schema in `db/schema.py`
2. Create a repository in `db/repositories/`
3. Wire writes through `db/writer.py`

**Adding a new tracker/analyzer:**
1. Create the module in `tracking/` or `analysis/`
2. Instantiate it in `dashboard/app.py` and feed it parsed packets
3. If it needs persistence, create a `db_` prefixed variant that wraps the in-memory version

**Adding a test:**
1. Create `tests/test_yourmodule.py`
2. Use existing fixtures from `conftest.py` (mock packets, parsed packets, temp DB, etc.)
3. Follow the naming convention: `test_*.py` files, `Test*` classes, `test_*` functions

**Modifying configuration:**
- All constants live in `config.py`. Modules import directly from it. There is no env-var or file-based config loading.
