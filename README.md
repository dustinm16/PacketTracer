# PacketTracer

A real-time network packet analysis tool with a terminal-based dashboard. PacketTracer captures network traffic, tracks flows, performs geo-location lookups, resolves hostnames, identifies network ownership, classifies traffic, and provides security analysis features.

## Features

- **Live Packet Capture** - Real-time capture using scapy with BPF filter support
- **Flow Tracking** - Bidirectional 5-tuple flow aggregation with statistics
- **Traffic Classification** - 18 categories (web, streaming, email, gaming, VoIP, P2P, etc.)
- **Geographic Resolution** - Country, city, ISP, ASN lookup via ip-api.com
- **DNS Resolution** - Reverse DNS with FQDN extraction
- **Network Ownership** - WHOIS/ASN lookups with regional registries
- **Security Analysis** - Port scan detection, IP reputation, alerting engine
- **Deep Packet Inspection** - OS fingerprinting, application detection, anomaly scoring
- **Connection Graphs** - ASCII visualization of network topology
- **Traceroute** - Active path tracing with RTT measurement and route history
- **Distributed Capture** - Remote agent support for multi-site monitoring

## Requirements

- Python 3.8+
- Root/sudo access (packet capture requires elevated privileges)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/packettracer.git
cd packettracer

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

- `scapy>=2.5.0` - Packet capture and parsing
- `rich>=13.0.0` - Terminal UI rendering
- `requests>=2.31.0` - HTTP API calls
- `cachetools>=5.3.0` - LRU caching

## Usage

```bash
# Run with auto-detected interface
sudo python main.py

# Run with specific interface
sudo python main.py -i eth0

# Apply BPF filter
sudo python main.py -f "tcp port 80"

# Start with traceroute to target
sudo python main.py -t 8.8.8.8

# List available interfaces
sudo python main.py --list

# Or use the wrapper script
./run.sh
```

## Keyboard Controls

| Key | Action |
|-----|--------|
| `1-5`, `6-0` | Switch between dashboard panels |
| Arrow keys | Navigate flows/entries |
| `Page Up/Down` | Scroll through entries |
| `Space` | Select/deselect flow |
| `Enter` | Run traceroute on selected |
| `/` | Filter by IP address |
| `:` | Filter by port |
| `p` | Pause/resume capture |
| `f` | Cycle protocol filter |
| `s` | Change sort order |
| `g` | Toggle destinations view |
| `a` | Select all flows |
| `c` | Clear selection |
| `q` | Quit |

## Dashboard Panels

1. **Traffic** - Live flow table with FQDN, geo info, and statistics
2. **Paths** - Traceroute results with route history and change detection
3. **Stats** - Country/ISP/protocol breakdown, top talkers
4. **Analysis** - Traffic classification, encryption detection
5. **Ports** - Port statistics, service breakdown, scan detection
6. **DNS** - Query/response analysis, domain frequency
7. **Relay** - Remote agent status and metrics
8. **Alerts** - Security alerts with acknowledgment
9. **Graph** - ASCII connection topology visualization
10. **DPI** - Deep packet inspection, OS detection

## Architecture

```
Capture Layer (libpcap via scapy)
    │
Tracking Layer (flows, ports, hops, classification)
    │
Resolution Layer (geo, DNS, ownership, reputation)
    │
Database Layer (SQLite with WAL, repositories)
    │
Security Layer (alerts, connection graphs, DPI)
    │
Dashboard Layer (Rich terminal UI)
```

### Threading Model

- **Main thread**: Dashboard loop (50ms cycle) handling input and UI updates
- **Background threads**: PacketSniffer, GeoResolver, DNSResolver, DatabaseWriter
- **SQLite WAL mode**: Enables concurrent reads during writes for lag-free UI

## Project Structure

```
packettracer/
├── main.py              # CLI entry point
├── config.py            # Configuration constants
├── requirements.txt     # Dependencies
├── run.sh               # Sudo wrapper script
├── capture/             # Packet capture and parsing
├── tracking/            # Flow analysis and classification
├── geo/                 # Geographic and DNS resolution
├── dashboard/           # Terminal UI and panels
├── db/                  # SQLite persistence layer
├── security/            # Alerts, reputation, graphs
├── analysis/            # Deep packet inspection
├── relay/               # Distributed capture agents
├── utils/               # Helper utilities
└── tests/               # Unit and integration tests
```

## Configuration

Key settings in `config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| Database path | `~/.packettracer/data.db` | SQLite database location |
| Geo rate limit | 45 req/min | ip-api.com rate limiting |
| Geo cache | 10,000 entries | In-memory cache size |
| DNS cache | 5,000 entries | In-memory cache size |
| Max flows | 50,000 | LRU eviction threshold |
| Flow timeout | 5 minutes | Idle flow expiration |
| Dashboard refresh | 100ms | UI update interval |
| Data retention | 30 days | Database cleanup period |

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_dpi.py -v
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit pull requests.
