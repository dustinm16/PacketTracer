"""Tests for capture/sniffer.py module."""

import pytest
from unittest.mock import MagicMock, patch
from capture.sniffer import PacketSniffer


class TestPacketSniffer:
    """Tests for PacketSniffer class."""

    def test_creation_default(self):
        """Test sniffer creation with defaults."""
        with patch('capture.sniffer.get_default_interface', return_value='eth0'):
            sniffer = PacketSniffer()
            assert sniffer.interface == 'eth0'
            assert sniffer.bpf_filter == 'ip'
            assert sniffer.callback is None
            assert sniffer.is_running() is False

    def test_creation_with_interface(self):
        """Test sniffer creation with specific interface."""
        sniffer = PacketSniffer(interface='lo')
        assert sniffer.interface == 'lo'

    def test_creation_with_filter(self):
        """Test sniffer creation with BPF filter."""
        sniffer = PacketSniffer(interface='lo', bpf_filter='tcp port 443')
        assert sniffer.bpf_filter == 'tcp port 443'

    def test_creation_with_callback(self):
        """Test sniffer creation with callback."""
        callback = MagicMock()
        sniffer = PacketSniffer(interface='lo', callback=callback)
        assert sniffer.callback == callback

    @patch('capture.sniffer.get_if_list')
    def test_list_interfaces(self, mock_get_if_list):
        """Test list_interfaces static method."""
        mock_get_if_list.return_value = ['lo', 'eth0', 'wlan0']

        interfaces = PacketSniffer.list_interfaces()

        assert interfaces == ['lo', 'eth0', 'wlan0']
        mock_get_if_list.assert_called_once()

    def test_packet_handler_with_callback(self):
        """Test packet handler calls callback when set."""
        callback = MagicMock()
        sniffer = PacketSniffer(interface='lo', callback=callback)

        mock_packet = MagicMock()
        sniffer._packet_handler(mock_packet)

        callback.assert_called_once_with(mock_packet)

    def test_packet_handler_without_callback(self):
        """Test packet handler queues packets when no callback."""
        sniffer = PacketSniffer(interface='lo')

        mock_packet = MagicMock()
        sniffer._packet_handler(mock_packet)

        assert sniffer.packet_queue.qsize() == 1
        assert sniffer.packet_queue.get() == mock_packet

    def test_is_running_initial(self):
        """Test is_running returns False initially."""
        sniffer = PacketSniffer(interface='lo')
        assert sniffer.is_running() is False

    def test_get_packet_empty_queue(self):
        """Test get_packet returns None for empty queue."""
        sniffer = PacketSniffer(interface='lo')
        packet = sniffer.get_packet(timeout=0.01)
        assert packet is None

    def test_get_packet_from_queue(self):
        """Test get_packet retrieves from queue."""
        sniffer = PacketSniffer(interface='lo')
        mock_packet = MagicMock()
        sniffer.packet_queue.put(mock_packet)

        packet = sniffer.get_packet(timeout=0.1)
        assert packet == mock_packet

    def test_stop_when_not_running(self):
        """Test stop is safe when not running."""
        sniffer = PacketSniffer(interface='lo')
        sniffer.stop()  # Should not raise
        assert sniffer.is_running() is False

    @pytest.mark.requires_root
    def test_start_stop_loopback(self):
        """Test starting and stopping on loopback (requires root)."""
        sniffer = PacketSniffer(interface='lo', bpf_filter='icmp')
        sniffer.start()

        assert sniffer.is_running() is True

        sniffer.stop()

        assert sniffer.is_running() is False

    @pytest.mark.requires_root
    def test_context_manager(self):
        """Test context manager usage (requires root)."""
        with PacketSniffer(interface='lo', bpf_filter='icmp') as sniffer:
            assert sniffer.is_running() is True

        assert sniffer.is_running() is False

    def test_double_start_safe(self):
        """Test that double start is safe."""
        sniffer = PacketSniffer(interface='lo')
        sniffer._running = True  # Simulate running

        sniffer.start()  # Should return early

        # Should still be "running"
        assert sniffer._running is True

    def test_sniff_thread_sets_running_false_on_exit(self):
        """Test that sniff thread sets _running to False on exit."""
        sniffer = PacketSniffer(interface='lo')
        sniffer._running = True
        sniffer._stop_event.set()

        # Simulate thread function with error
        with patch('capture.sniffer.sniff', side_effect=Exception("Test error")):
            sniffer._sniff_thread()

        assert sniffer._running is False


class TestPacketSnifferIntegration:
    """Integration tests for PacketSniffer (may require privileges)."""

    @pytest.mark.requires_root
    @pytest.mark.integration
    def test_capture_loopback_traffic(self):
        """Test capturing traffic on loopback interface."""
        import subprocess
        import time

        packets_received = []

        def callback(packet):
            packets_received.append(packet)

        sniffer = PacketSniffer(
            interface='lo',
            bpf_filter='icmp',
            callback=callback
        )

        try:
            sniffer.start()

            # Generate some ICMP traffic
            subprocess.Popen(
                ['ping', '-c', '3', '127.0.0.1'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(1)

        finally:
            sniffer.stop()

        # Should have captured some packets
        assert len(packets_received) > 0
