"""Configuration constants for the packet tracker."""

# Capture settings
DEFAULT_INTERFACE = None  # None means auto-detect
CAPTURE_FILTER = "ip"  # BPF filter - capture only IP packets
SNAP_LENGTH = 65535  # Maximum bytes to capture per packet

# Geo API settings
GEO_API_URL = "http://ip-api.com/json/{ip}"
GEO_API_BATCH_URL = "http://ip-api.com/batch"
GEO_API_RATE_LIMIT = 45  # Requests per minute
GEO_CACHE_SIZE = 10000  # Maximum cached entries
GEO_CACHE_TTL = 3600  # Cache TTL in seconds (1 hour)
GEO_API_HOST = "ip-api.com"  # Hostname to filter from capture

# Dashboard settings
REFRESH_RATE = 0.1  # Dashboard refresh rate in seconds (100ms for responsive UI)
MAX_FLOWS_DISPLAY = 50  # Maximum flows to show in traffic panel
MAX_PATHS_DISPLAY = 20  # Maximum paths to show in paths panel

# DNS/Hostname resolution settings
DNS_CACHE_SIZE = 5000  # Maximum cached hostname lookups
DNS_CACHE_TTL = 3600  # DNS cache TTL in seconds (1 hour)
DNS_TIMEOUT = 1.0  # DNS lookup timeout in seconds

# Flow tracking settings
FLOW_TIMEOUT = 300  # Flow timeout in seconds (5 minutes)
MAX_FLOWS = 50000  # Maximum tracked flows before pruning

# Traceroute settings
TRACEROUTE_MAX_HOPS = 30  # Maximum hops for traceroute
TRACEROUTE_TIMEOUT = 2  # Timeout per hop in seconds
TRACEROUTE_PROBES = 3  # Number of probes per hop

# TTL defaults for OS detection
DEFAULT_TTL = {
    "linux": 64,
    "windows": 128,
    "macos": 64,
    "cisco": 255,
    "solaris": 255,
}

# Protocol names
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}

# Database settings
DB_PATH = "~/.packettracer/data.db"  # Database file location
DB_READ_POOL_SIZE = 4  # Number of read connections
DB_WRITE_BATCH_SIZE = 100  # Batch size for writes
DB_WRITE_FLUSH_MS = 100  # Flush interval in milliseconds
DB_WAL_MODE = True  # Use WAL mode for concurrent access
DB_GEO_CACHE_TTL = 86400  # 24 hours (longer for persistent cache)
DB_DNS_CACHE_TTL = 3600  # 1 hour
DB_NS_CACHE_TTL = 86400  # 24 hours for NS records
DB_SESSION_RETENTION_DAYS = 30  # Keep sessions for 30 days

# Device type classifications
DEVICE_TYPES = [
    "unknown",
    "endpoint",
    "workstation",
    "server",
    "router",
    "switch",
    "firewall",
    "load_balancer",
    "proxy",
    "iot",
    "mobile",
    "printer",
    "camera",
    "voip_phone",
    "access_point",
]

# Device role classifications
DEVICE_ROLES = [
    "gateway",
    "dns_server",
    "dhcp_server",
    "web_server",
    "mail_server",
    "file_server",
    "database_server",
    "domain_controller",
    "monitoring",
    "backup",
]

# Relay server settings
RELAY_SERVER_HOST = "0.0.0.0"  # Listen address for relay server
RELAY_SERVER_PORT = 8765  # WebSocket port
RELAY_SERVER_CERT_FILE = None  # Path to TLS certificate (None for unencrypted)
RELAY_SERVER_KEY_FILE = None  # Path to TLS private key
RELAY_AGENT_HEARTBEAT_INTERVAL = 30  # Seconds between agent heartbeats
RELAY_AGENT_METRICS_INTERVAL = 60  # Seconds between metrics reports
RELAY_AGENT_FLOW_INTERVAL = 10  # Seconds between flow data reports
RELAY_DATA_RETENTION_DAYS = 30  # Days to keep relay agent data
RELAY_MAX_MESSAGE_SIZE = 1024 * 1024  # Maximum message size (1MB)

# IP Reputation settings (AbuseIPDB)
REPUTATION_API_KEY = None  # Set to your AbuseIPDB API key
REPUTATION_CACHE_SIZE = 10000  # Maximum cached reputation lookups
REPUTATION_CACHE_TTL = 86400  # 24 hours
REPUTATION_RATE_LIMIT = 1000  # Requests per day (AbuseIPDB free tier)
REPUTATION_CHECK_ENABLED = True  # Enable/disable reputation checking

# Alerting settings
ALERTS_ENABLED = True
ALERTS_MAX_STORED = 1000  # Maximum alerts to keep in memory
ALERTS_PORT_SCAN_THRESHOLD = 10  # Unique ports before triggering port scan alert
ALERTS_HIGH_BANDWIDTH_MB = 100  # MB threshold for high bandwidth alert
ALERTS_CONNECTION_SPIKE = 100  # New connections/second threshold

# Connection graph settings
GRAPH_MAX_NODES = 100  # Maximum nodes to track in graph
GRAPH_MIN_BYTES = 1000  # Minimum bytes to include edge in graph
