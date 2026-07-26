"""
PacketVision Pro - Packet Capture Engine
==========================================

Provides real-time network packet capture using Scapy's sniff() function,
running in a dedicated background thread. Captured packets are parsed
immediately and passed to registered callbacks for GUI display, database
storage, and threat detection.

Architecture:
    The capture engine runs two background threads:
    1. Capture thread - Runs Scapy's sniff() and processes each packet
    2. Stats thread   - Periodically sends statistics updates to the callback

    Packets flow: Network -> Scapy sniff -> ProtocolParser -> callback
                  (capture thread)                (main thread)

Key Classes:
    PacketCaptureEngine  - Low-level capture engine with threading
    LiveCaptureManager   - Higher-level manager for GUI integration
    CaptureStats         - Real-time statistics tracker

Usage:
    engine = PacketCaptureEngine(
        interface="eth0",
        bpf_filter="tcp port 80",
        packet_callback=my_callback,
        stats_callback=my_stats_callback
    )
    engine.start()
    # ... later ...
    engine.stop()
"""

import logging
import threading
import time
from typing import Callable, Optional, Dict, Any, List
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field
from scapy.all import sniff, conf, get_if_list, get_if_addr, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw
import queue

try:
    from scapy.arch import get_if_raw_hwaddr
except ImportError:
    def get_if_raw_hwaddr(iface):
        """Fallback MAC address lookup."""
        try:
            import uuid
            mac = uuid.getnode()
            mac_str = ':'.join(f'{(mac >> (8 * i)) & 0xff:02x}' for i in reversed(range(6)))
            return ('eth', mac_str.encode())
        except Exception:
            return ('eth', b'\x00\x00\x00\x00\x00\x00')

logger = logging.getLogger(__name__)


@dataclass
class CaptureStats:
    """Capture statistics."""
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    src_ip_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dst_ip_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    src_port_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    dst_port_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    errors: int = 0
    dropped: int = 0

    def update(self, packet_data: dict):
        """Update statistics with a packet."""
        self.total_packets += 1
        self.total_bytes += packet_data.get('packet_length', 0)
        proto = packet_data.get('protocol_name', 'Unknown')
        self.protocol_counts[proto] += 1
        
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        src_port = packet_data.get('src_port')
        dst_port = packet_data.get('dst_port')
        
        if src_ip:
            self.src_ip_counts[src_ip] += 1
        if dst_ip:
            self.dst_ip_counts[dst_ip] += 1
        if src_port:
            self.src_port_counts[src_port] += 1
        if dst_port:
            self.dst_port_counts[dst_port] += 1
        
        now = time.time()
        elapsed = now - self.start_time
        if elapsed > 0:
            self.packets_per_second = self.total_packets / elapsed
            self.bytes_per_second = self.total_bytes / elapsed
        self.last_update = now

    def get_summary(self) -> Dict[str, Any]:
        """Get statistics summary."""
        elapsed = time.time() - self.start_time
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_per_second': round(self.packets_per_second, 2),
            'bytes_per_second': round(self.bytes_per_second, 2),
            'elapsed_seconds': round(elapsed, 1),
            'protocol_counts': dict(self.protocol_counts),
            'top_src_ips': dict(sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_dst_ips': dict(sorted(self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_src_ports': dict(sorted(self.src_port_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_dst_ports': dict(sorted(self.dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'errors': self.errors,
            'dropped': self.dropped,
        }


class PacketCaptureEngine:
    """High-performance packet capture engine using Scapy."""

    def __init__(
        self,
        interface: str = None,
        bpf_filter: str = None,
        packet_callback: Callable[[Dict[str, Any]], None] = None,
        stats_callback: Callable[[Dict[str, Any]], None] = None,
        buffer_size: int = 10000,
        promiscuous: bool = True,
        store_packets: bool = True,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_callback = packet_callback
        self.stats_callback = stats_callback
        self.buffer_size = buffer_size
        self.promiscuous = promiscuous
        self.store_packets = store_packets
        
        self._running = False
        self._paused = False
        self._thread: Optional[threading.Thread] = None
        self._stats_thread: Optional[threading.Thread] = None
        self._packet_queue: queue.Queue = queue.Queue(maxsize=buffer_size)
        self._stats = CaptureStats()
        self._packet_buffer: deque = deque(maxlen=buffer_size)
        self._lock = threading.RLock()
        
        # Import protocol parser
        from core.protocols import ProtocolParser
        self._parser = ProtocolParser()
        
        # Statistics update interval (seconds)
        self._stats_interval = 1.0

    def start(self) -> bool:
        """Start packet capture."""
        if self._running:
            logger.warning("Capture already running")
            return False
        
        # Validate interface
        if not self.interface:
            self.interface = conf.iface
            logger.info(f"Using default interface: {self.interface}")
        
        if self.interface not in get_if_list():
            logger.error(f"Interface {self.interface} not found")
            return False
        
        self._running = True
        self._paused = False
        self._stats = CaptureStats()
        self._packet_buffer.clear()
        
        # Start capture thread
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        
        # Start stats thread
        self._stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        self._stats_thread.start()
        
        logger.info(f"Capture started on interface {self.interface}")
        return True

    def stop(self):
        """Stop packet capture."""
        if not self._running:
            return
        
        self._running = False
        self._paused = False
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=1.0)
        
        logger.info("Capture stopped")

    def pause(self):
        """Pause packet capture."""
        self._paused = True
        logger.info("Capture paused")

    def resume(self):
        """Resume packet capture."""
        self._paused = False
        logger.info("Capture resumed")

    def is_running(self) -> bool:
        """Check if capture is running."""
        return self._running

    def is_paused(self) -> bool:
        """Check if capture is paused."""
        return self._paused

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        with self._lock:
            return self._stats.get_summary()

    def get_buffered_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get buffered packets."""
        with self._lock:
            return self._packet_buffer[-limit:] if self._packet_buffer else []

    def clear_buffer(self):
        """Clear packet buffer."""
        with self._lock:
            self._packet_buffer.clear()

    def set_filter(self, bpf_filter: str):
        """Update BPF filter."""
        self.bpf_filter = bpf_filter
        logger.info(f"BPF filter updated: {bpf_filter}")

    def set_interface(self, interface: str) -> bool:
        """Change capture interface."""
        if interface not in get_if_list():
            logger.error(f"Interface {interface} not found")
            return False
        
        was_running = self._running
        if was_running:
            self.stop()
        
        self.interface = interface
        
        if was_running:
            self.start()
        
        return True

    def _capture_loop(self):
        """Main packet capture loop."""
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                stop_filter=lambda _: not self._running,
                store=False,
                promisc=self.promiscuous,
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self._stats.errors += 1
        finally:
            self._running = False

    def _stats_loop(self):
        """Statistics update loop."""
        while self._running:
            time.sleep(self._stats_interval)
            if self._running and not self._paused and self.stats_callback:
                try:
                    self.stats_callback(self._stats.get_summary())
                except Exception as e:
                    logger.error(f"Stats callback error: {e}")

    def _process_packet(self, packet):
        """Process a captured packet."""
        if self._paused or not self._running:
            return
        
        try:
            # Parse packet
            packet_data = self._parser.parse_packet(packet)
            
            # Update statistics
            self._stats.update(packet_data)
            
            # Add to buffer if storing (deque auto-evicts oldest when full)
            if self.store_packets:
                with self._lock:
                    self._packet_buffer.append(packet_data)
            
            # Callback with packet data
            if self.packet_callback:
                try:
                    self.packet_callback(packet_data)
                except Exception as e:
                    logger.error(f"Packet callback error: {e}")
                    self._stats.errors += 1
        
        except Exception as e:
            logger.error(f"Packet processing error: {e}", exc_info=True)
            self._stats.errors += 1

    @staticmethod
    def get_interfaces() -> List[Dict[str, Any]]:
        """Get list of available network interfaces."""
        interfaces = []
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                mac = get_if_raw_hwaddr(iface)[1]
                mac_str = ':'.join(f'{b:02x}' for b in mac).upper()
            except Exception:
                ip = 'N/A'
                mac_str = 'N/A'
            
            interfaces.append({
                'name': iface,
                'ip': ip,
                'mac': mac_str,
            })
        return interfaces

    @staticmethod
    def get_default_interface() -> str:
        """Get default interface."""
        return conf.iface


class LiveCaptureManager:
    """High-level capture manager for GUI integration."""

    def __init__(self):
        self.engine: Optional[PacketCaptureEngine] = None
        self._callbacks: Dict[str, Callable] = {}

    def set_callbacks(
        self,
        on_packet: Callable[[Dict], None] = None,
        on_stats: Callable[[Dict], None] = None,
        on_alert: Callable[[Dict], None] = None,
        on_error: Callable[[str], None] = None,
    ):
        """Set callback functions."""
        self._callbacks = {
            'packet': on_packet,
            'stats': on_stats,
            'alert': on_alert,
            'error': on_error,
        }

    def start_capture(
        self,
        interface: str = None,
        bpf_filter: str = None,
        buffer_size: int = 10000,
        promiscuous: bool = True,
    ) -> bool:
        """Start capture with callbacks."""
        def packet_cb(pkt):
            if self._callbacks.get('packet'):
                self._callbacks['packet'](pkt)
        
        def stats_cb(stats):
            if self._callbacks.get('stats'):
                self._callbacks['stats'](stats)
        
        self.engine = PacketCaptureEngine(
            interface=interface,
            bpf_filter=bpf_filter,
            packet_callback=packet_cb,
            stats_callback=stats_cb,
            buffer_size=buffer_size,
            promiscuous=promiscuous,
        )
        return self.engine.start()

    def stop_capture(self):
        """Stop capture."""
        if self.engine:
            self.engine.stop()
            self.engine = None

    def pause_capture(self):
        """Pause capture."""
        if self.engine:
            self.engine.pause()

    def resume_capture(self):
        """Resume capture."""
        if self.engine:
            self.engine.resume()

    def get_stats(self) -> Dict:
        """Get current stats."""
        if self.engine:
            return self.engine.get_stats()
        return {}

    def get_interfaces(self) -> List[Dict]:
        """Get available interfaces."""
        return PacketCaptureEngine.get_interfaces()

    def set_filter(self, bpf_filter: str):
        """Set BPF filter."""
        if self.engine:
            self.engine.set_filter(bpf_filter)

    def is_running(self) -> bool:
        """Check if capture is running."""
        return self.engine and self.engine.is_running()

    def is_paused(self) -> bool:
        """Check if capture is paused."""
        return self.engine and self.engine.is_paused()


# Convenience function
def create_capture_engine(
    interface: str = None,
    bpf_filter: str = None,
    packet_callback: Callable = None,
    stats_callback: Callable = None,
) -> PacketCaptureEngine:
    """Factory function to create a capture engine."""
    return PacketCaptureEngine(
        interface=interface,
        bpf_filter=bpf_filter,
        packet_callback=packet_callback,
        stats_callback=stats_callback,
    )
