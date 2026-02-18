"""Packet capture using scapy."""

import threading
from typing import Callable, Optional, List
from queue import Queue

from scapy.all import sniff, get_if_list
from scapy.packet import Packet

from config import DEFAULT_INTERFACE, CAPTURE_FILTER
from utils.network import get_default_interface


class PacketSniffer:
    """Captures network packets using scapy."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = CAPTURE_FILTER,
        callback: Optional[Callable[[Packet], None]] = None,
    ):
        self.interface = interface or get_default_interface() or DEFAULT_INTERFACE
        self.bpf_filter = bpf_filter
        self.callback = callback
        self.packet_queue: Queue = Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @staticmethod
    def list_interfaces() -> List[str]:
        """List available network interfaces."""
        return get_if_list()

    def _packet_handler(self, packet: Packet) -> None:
        """Handle captured packets."""
        if self.callback:
            self.callback(packet)
        else:
            self.packet_queue.put(packet)

    def _sniff_thread(self) -> None:
        """Sniffing thread function."""
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as e:
            print(f"Sniffer error: {e}")
        finally:
            self._running = False

    def start(self) -> None:
        """Start packet capture in a background thread."""
        if self._running:
            return

        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(target=self._sniff_thread, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop packet capture."""
        self._stop_event.set()
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def is_running(self) -> bool:
        """Check if sniffer is running."""
        return self._running

    def get_packet(self, timeout: float = 0.1) -> Optional[Packet]:
        """Get a packet from the queue (when no callback is set)."""
        try:
            return self.packet_queue.get(timeout=timeout)
        except Exception:
            return None

    def __enter__(self) -> "PacketSniffer":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
