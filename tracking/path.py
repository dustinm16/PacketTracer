"""Active traceroute functionality."""

import socket
import struct
import time
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict
from concurrent.futures import ThreadPoolExecutor

from scapy.all import IP, ICMP, UDP, sr1, conf

from config import TRACEROUTE_MAX_HOPS, TRACEROUTE_TIMEOUT, TRACEROUTE_PROBES


# Disable scapy verbosity
conf.verb = 0


@dataclass
class HopResult:
    """Result from probing a single hop."""

    ttl: int
    ip: Optional[str] = None
    hostname: Optional[str] = None
    rtt_ms: List[float] = field(default_factory=list)
    is_destination: bool = False
    is_timeout: bool = False

    @property
    def avg_rtt(self) -> Optional[float]:
        if not self.rtt_ms:
            return None
        return sum(self.rtt_ms) / len(self.rtt_ms)

    @property
    def min_rtt(self) -> Optional[float]:
        if not self.rtt_ms:
            return None
        return min(self.rtt_ms)

    @property
    def max_rtt(self) -> Optional[float]:
        if not self.rtt_ms:
            return None
        return max(self.rtt_ms)


@dataclass
class TracerouteResult:
    """Complete traceroute result."""

    target: str
    target_ip: str
    hops: List[HopResult]
    completed: bool
    start_time: float
    end_time: float

    @property
    def total_hops(self) -> int:
        return len([h for h in self.hops if h.ip is not None])

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time


class PathTracer:
    """Performs active traceroute to map network paths."""

    def __init__(
        self,
        max_hops: int = TRACEROUTE_MAX_HOPS,
        timeout: float = TRACEROUTE_TIMEOUT,
        probes: int = TRACEROUTE_PROBES,
    ):
        self.max_hops = max_hops
        self.timeout = timeout
        self.probes = probes
        self._cache: Dict[str, TracerouteResult] = {}
        self._lock = threading.Lock()
        self._running_traces: Dict[str, threading.Event] = {}

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None

    def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return target

    def _probe_hop(self, target_ip: str, ttl: int, use_udp: bool = False) -> HopResult:
        """Send probes to a single hop and collect results."""
        result = HopResult(ttl=ttl)
        rtt_list = []
        responding_ip = None

        for _ in range(self.probes):
            start_time = time.time()

            if use_udp:
                # UDP probe (port 33434 + ttl, common traceroute behavior)
                packet = IP(dst=target_ip, ttl=ttl) / UDP(dport=33434 + ttl, sport=33434)
            else:
                # ICMP probe
                packet = IP(dst=target_ip, ttl=ttl) / ICMP()

            reply = sr1(packet, timeout=self.timeout, verbose=0)

            if reply:
                rtt = (time.time() - start_time) * 1000  # Convert to ms
                rtt_list.append(rtt)
                responding_ip = reply.src

                # Check if we reached the destination
                if reply.src == target_ip:
                    result.is_destination = True
                    break

                # ICMP Time Exceeded (type 11) means intermediate hop
                # ICMP Destination Unreachable (type 3) for UDP probes at destination
                if reply.haslayer(ICMP):
                    icmp = reply[ICMP]
                    if icmp.type == 3:  # Destination unreachable (UDP reached dest)
                        result.is_destination = True
                        break

        if responding_ip:
            result.ip = responding_ip
            result.hostname = self._resolve_hostname(responding_ip)
            result.rtt_ms = rtt_list
        else:
            result.is_timeout = True

        return result

    def trace(
        self,
        target: str,
        use_udp: bool = False,
        callback: Optional[Callable[[HopResult], None]] = None,
    ) -> TracerouteResult:
        """Perform a traceroute to the target."""
        target_ip = self._resolve_target(target)
        start_time = time.time()
        hops = []
        completed = False

        # Check if already running
        with self._lock:
            if target_ip in self._running_traces:
                # Wait for existing trace to complete
                event = self._running_traces[target_ip]
                event.wait()
                if target_ip in self._cache:
                    return self._cache[target_ip]
            self._running_traces[target_ip] = threading.Event()

        try:
            for ttl in range(1, self.max_hops + 1):
                hop_result = self._probe_hop(target_ip, ttl, use_udp)
                hops.append(hop_result)

                if callback:
                    callback(hop_result)

                if hop_result.is_destination:
                    completed = True
                    break

            result = TracerouteResult(
                target=target,
                target_ip=target_ip,
                hops=hops,
                completed=completed,
                start_time=start_time,
                end_time=time.time(),
            )

            # Cache result
            with self._lock:
                self._cache[target_ip] = result

            return result

        finally:
            with self._lock:
                if target_ip in self._running_traces:
                    self._running_traces[target_ip].set()
                    del self._running_traces[target_ip]

    def trace_async(
        self,
        target: str,
        use_udp: bool = False,
        callback: Optional[Callable[[TracerouteResult], None]] = None,
    ) -> None:
        """Perform traceroute asynchronously."""
        def _trace():
            result = self.trace(target, use_udp)
            if callback:
                callback(result)

        thread = threading.Thread(target=_trace, daemon=True)
        thread.start()

    def get_cached(self, target: str) -> Optional[TracerouteResult]:
        """Get cached traceroute result."""
        target_ip = self._resolve_target(target)
        with self._lock:
            return self._cache.get(target_ip)

    def clear_cache(self) -> None:
        """Clear traceroute cache."""
        with self._lock:
            self._cache.clear()
