"""TCP connection state tracking and analysis."""

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional

from capture.parser import ParsedPacket

logger = logging.getLogger(__name__)


class TCPState(Enum):
    """TCP connection states."""
    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RECEIVED = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSE_WAIT = auto()
    CLOSING = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()


@dataclass
class TCPConnection:
    """Represents a TCP connection with state tracking."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    state: TCPState = TCPState.CLOSED

    # Timing
    first_seen: float = 0.0
    last_seen: float = 0.0
    syn_time: Optional[float] = None
    syn_ack_time: Optional[float] = None
    established_time: Optional[float] = None
    fin_time: Optional[float] = None

    # RTT measurements
    rtt_samples: List[float] = field(default_factory=list)

    # Sequence tracking
    initial_seq_client: Optional[int] = None
    initial_seq_server: Optional[int] = None
    last_seq_client: int = 0
    last_seq_server: int = 0
    last_ack_client: int = 0
    last_ack_server: int = 0

    # Statistics
    packets_client: int = 0
    packets_server: int = 0
    bytes_client: int = 0
    bytes_server: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    duplicate_acks: int = 0

    # Window tracking
    window_sizes_client: List[int] = field(default_factory=list)
    window_sizes_server: List[int] = field(default_factory=list)

    @property
    def connection_key(self) -> str:
        """Unique key for this connection."""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"

    @property
    def reverse_key(self) -> str:
        """Reverse connection key."""
        return f"{self.dst_ip}:{self.dst_port}-{self.src_ip}:{self.src_port}"

    @property
    def handshake_rtt(self) -> Optional[float]:
        """RTT from SYN to SYN-ACK (milliseconds)."""
        if self.syn_time and self.syn_ack_time:
            return (self.syn_ack_time - self.syn_time) * 1000
        return None

    @property
    def avg_rtt(self) -> Optional[float]:
        """Average RTT in milliseconds."""
        if self.rtt_samples:
            return sum(self.rtt_samples) / len(self.rtt_samples)
        return None

    @property
    def min_rtt(self) -> Optional[float]:
        """Minimum RTT in milliseconds."""
        if self.rtt_samples:
            return min(self.rtt_samples)
        return None

    @property
    def max_rtt(self) -> Optional[float]:
        """Maximum RTT in milliseconds."""
        if self.rtt_samples:
            return max(self.rtt_samples)
        return None

    @property
    def avg_window_client(self) -> int:
        """Average window size from client."""
        if self.window_sizes_client:
            return int(sum(self.window_sizes_client) / len(self.window_sizes_client))
        return 0

    @property
    def avg_window_server(self) -> int:
        """Average window size from server."""
        if self.window_sizes_server:
            return int(sum(self.window_sizes_server) / len(self.window_sizes_server))
        return 0

    @property
    def duration(self) -> float:
        """Connection duration in seconds."""
        return self.last_seen - self.first_seen

    @property
    def total_packets(self) -> int:
        """Total packets in both directions."""
        return self.packets_client + self.packets_server

    @property
    def total_bytes(self) -> int:
        """Total bytes in both directions."""
        return self.bytes_client + self.bytes_server

    @property
    def retransmission_rate(self) -> float:
        """Retransmission rate as percentage."""
        if self.total_packets == 0:
            return 0.0
        return (self.retransmissions / self.total_packets) * 100

    @property
    def is_active(self) -> bool:
        """Check if connection is still active."""
        return self.state in (TCPState.ESTABLISHED, TCPState.SYN_SENT, TCPState.SYN_RECEIVED)

    def is_expired(self, timeout: float = 300.0, now: Optional[float] = None) -> bool:
        """Check if connection has timed out."""
        if now is None:
            now = time.time()
        return (now - self.last_seen) > timeout


class TCPStateTracker:
    """Track TCP connection states and statistics."""

    def __init__(self, max_connections: int = 10000, timeout: float = 300.0):
        self.max_connections = max_connections
        self.timeout = timeout
        self._connections: OrderedDict[str, TCPConnection] = OrderedDict()
        self._lock = threading.Lock()

        # Statistics
        self.total_syns = 0
        self.total_established = 0
        self.total_resets = 0
        self.total_fins = 0

    def process_packet(self, packet: ParsedPacket) -> Optional[TCPConnection]:
        """Process a TCP packet and update connection state.

        Args:
            packet: Parsed packet to process

        Returns:
            Updated TCPConnection if TCP packet, None otherwise
        """
        if packet.protocol_name != "TCP" or packet.flags is None:
            return None

        # Parse TCP flags
        flags = self._parse_flags(packet.flags)

        with self._lock:
            # Find or create connection
            conn = self._get_or_create_connection(packet)

            # Determine direction
            is_client_to_server = (
                packet.src_ip == conn.src_ip and
                packet.src_port == conn.src_port
            )

            # Update timestamps
            conn.last_seen = packet.timestamp
            if conn.first_seen == 0:
                conn.first_seen = packet.timestamp

            # Update packet/byte counts
            if is_client_to_server:
                conn.packets_client += 1
                conn.bytes_client += packet.length
            else:
                conn.packets_server += 1
                conn.bytes_server += packet.length

            # Track window size
            if hasattr(packet, 'window') and packet.window:
                if is_client_to_server:
                    conn.window_sizes_client.append(packet.window)
                    if len(conn.window_sizes_client) > 100:
                        conn.window_sizes_client = conn.window_sizes_client[-100:]
                else:
                    conn.window_sizes_server.append(packet.window)
                    if len(conn.window_sizes_server) > 100:
                        conn.window_sizes_server = conn.window_sizes_server[-100:]

            # Update state based on flags
            self._update_state(conn, packet, flags, is_client_to_server)

            # Track sequence numbers for retransmission detection
            self._track_sequences(conn, packet, is_client_to_server)

            # Move to end for LRU
            self._connections.move_to_end(conn.connection_key)

            # Prune if needed
            if len(self._connections) > self.max_connections:
                self._prune_connections()

            return conn

    def _parse_flags(self, flags_str: str) -> Dict[str, bool]:
        """Parse TCP flags string into dict."""
        return {
            'SYN': 'S' in flags_str,
            'ACK': 'A' in flags_str,
            'FIN': 'F' in flags_str,
            'RST': 'R' in flags_str,
            'PSH': 'P' in flags_str,
            'URG': 'U' in flags_str,
        }

    def _get_or_create_connection(self, packet: ParsedPacket) -> TCPConnection:
        """Get existing connection or create new one."""
        # Check both directions
        key1 = f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}"
        key2 = f"{packet.dst_ip}:{packet.dst_port}-{packet.src_ip}:{packet.src_port}"

        if key1 in self._connections:
            return self._connections[key1]
        if key2 in self._connections:
            return self._connections[key2]

        # Create new connection (initiator is client)
        conn = TCPConnection(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            first_seen=packet.timestamp,
            last_seen=packet.timestamp,
        )
        self._connections[conn.connection_key] = conn
        return conn

    def _update_state(
        self,
        conn: TCPConnection,
        packet: ParsedPacket,
        flags: Dict[str, bool],
        is_client: bool
    ) -> None:
        """Update connection state based on TCP flags."""
        if flags['RST']:
            conn.state = TCPState.CLOSED
            self.total_resets += 1
            return

        if flags['SYN'] and not flags['ACK']:
            # SYN - connection initiation
            if conn.state == TCPState.CLOSED:
                conn.state = TCPState.SYN_SENT
                conn.syn_time = packet.timestamp
                conn.initial_seq_client = packet.seq
                self.total_syns += 1

        elif flags['SYN'] and flags['ACK']:
            # SYN-ACK - server response
            if conn.state == TCPState.SYN_SENT:
                conn.state = TCPState.SYN_RECEIVED
                conn.syn_ack_time = packet.timestamp
                conn.initial_seq_server = packet.seq
                # Calculate handshake RTT
                if conn.syn_time:
                    rtt = (packet.timestamp - conn.syn_time) * 1000
                    conn.rtt_samples.append(rtt)

        elif flags['ACK'] and not flags['SYN'] and not flags['FIN']:
            # ACK - various transitions
            if conn.state == TCPState.SYN_RECEIVED:
                conn.state = TCPState.ESTABLISHED
                conn.established_time = packet.timestamp
                self.total_established += 1
            elif conn.state == TCPState.FIN_WAIT_1:
                conn.state = TCPState.FIN_WAIT_2
            elif conn.state == TCPState.CLOSING:
                conn.state = TCPState.TIME_WAIT
            elif conn.state == TCPState.LAST_ACK:
                conn.state = TCPState.CLOSED

        elif flags['FIN']:
            # FIN - connection termination
            self.total_fins += 1
            if conn.fin_time is None:
                conn.fin_time = packet.timestamp

            if conn.state == TCPState.ESTABLISHED:
                if is_client:
                    conn.state = TCPState.FIN_WAIT_1
                else:
                    conn.state = TCPState.CLOSE_WAIT
            elif conn.state == TCPState.FIN_WAIT_1:
                conn.state = TCPState.CLOSING
            elif conn.state == TCPState.FIN_WAIT_2:
                conn.state = TCPState.TIME_WAIT
            elif conn.state == TCPState.CLOSE_WAIT:
                conn.state = TCPState.LAST_ACK

    @staticmethod
    def _seq_before(a: int, b: int) -> bool:
        """Check if TCP sequence number a comes before b (handles 32-bit wraparound).

        Uses the standard TCP comparison: a < b iff (b - a) mod 2^32 < 2^31.
        """
        diff = (b - a) & 0xFFFFFFFF
        return 0 < diff < 0x80000000

    def _track_sequences(
        self,
        conn: TCPConnection,
        packet: ParsedPacket,
        is_client: bool
    ) -> None:
        """Track sequence numbers for retransmission and out-of-order detection."""
        if packet.seq is None:
            return

        if is_client:
            if conn.last_seq_client != 0:
                if packet.seq == conn.last_seq_client:
                    # Same seq as last — possible duplicate/retransmission
                    conn.retransmissions += 1
                elif self._seq_before(packet.seq, conn.last_seq_client):
                    # Seq is older than last seen — retransmission or out-of-order
                    conn.retransmissions += 1
                    conn.out_of_order += 1
            conn.last_seq_client = packet.seq
            if packet.ack:
                if packet.ack == conn.last_ack_client and conn.last_ack_client != 0:
                    conn.duplicate_acks += 1
                conn.last_ack_client = packet.ack
        else:
            if conn.last_seq_server != 0:
                if packet.seq == conn.last_seq_server:
                    conn.retransmissions += 1
                elif self._seq_before(packet.seq, conn.last_seq_server):
                    conn.retransmissions += 1
                    conn.out_of_order += 1
            conn.last_seq_server = packet.seq
            if packet.ack:
                if packet.ack == conn.last_ack_server and conn.last_ack_server != 0:
                    conn.duplicate_acks += 1
                conn.last_ack_server = packet.ack

    def _prune_connections(self) -> None:
        """Remove expired or oldest connections."""
        now = time.time()

        # Remove expired
        expired = [
            key for key, conn in self._connections.items()
            if conn.is_expired(self.timeout, now=now)
        ]
        for key in expired:
            del self._connections[key]

        # If still over limit, remove oldest
        while len(self._connections) > self.max_connections:
            self._connections.popitem(last=False)

    def get_connection(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[TCPConnection]:
        """Get a specific connection."""
        key1 = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        key2 = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

        with self._lock:
            return self._connections.get(key1) or self._connections.get(key2)

    def get_connections(self, state: Optional[TCPState] = None) -> List[TCPConnection]:
        """Get all connections, optionally filtered by state."""
        with self._lock:
            conns = list(self._connections.values())

        if state:
            conns = [c for c in conns if c.state == state]

        return conns

    def get_active_connections(self) -> List[TCPConnection]:
        """Get all active (established) connections."""
        return self.get_connections(TCPState.ESTABLISHED)

    def get_top_by_bytes(self, n: int = 10) -> List[TCPConnection]:
        """Get top N connections by total bytes."""
        with self._lock:
            conns = list(self._connections.values())
        conns.sort(key=lambda c: c.total_bytes, reverse=True)
        return conns[:n]

    def get_top_by_rtt(self, n: int = 10) -> List[TCPConnection]:
        """Get top N connections by average RTT."""
        with self._lock:
            conns = [c for c in self._connections.values() if c.avg_rtt]
        conns.sort(key=lambda c: c.avg_rtt or 0, reverse=True)
        return conns[:n]

    def get_retransmission_stats(self) -> Dict[str, int]:
        """Get connections with retransmissions."""
        with self._lock:
            conns = list(self._connections.values())

        total_retrans = sum(c.retransmissions for c in conns)
        conns_with_retrans = sum(1 for c in conns if c.retransmissions > 0)

        return {
            "total_retransmissions": total_retrans,
            "connections_with_retransmissions": conns_with_retrans,
            "total_connections": len(conns),
        }

    def get_state_summary(self) -> Dict[str, int]:
        """Get count of connections by state."""
        with self._lock:
            conns = list(self._connections.values())

        summary = {state.name: 0 for state in TCPState}
        for conn in conns:
            summary[conn.state.name] += 1

        return summary

    def get_stats(self) -> Dict[str, any]:
        """Get tracker statistics."""
        with self._lock:
            conn_count = len(self._connections)

        return {
            "total_connections": conn_count,
            "total_syns": self.total_syns,
            "total_established": self.total_established,
            "total_resets": self.total_resets,
            "total_fins": self.total_fins,
            "state_summary": self.get_state_summary(),
            "retransmission_stats": self.get_retransmission_stats(),
        }

    def cleanup_expired(self) -> int:
        """Remove expired connections and return count removed."""
        with self._lock:
            initial_count = len(self._connections)
            self._prune_connections()
            return initial_count - len(self._connections)

    @property
    def connection_count(self) -> int:
        """Get current number of tracked connections."""
        with self._lock:
            return len(self._connections)
