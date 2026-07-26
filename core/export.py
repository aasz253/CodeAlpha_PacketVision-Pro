"""
PacketVision Pro - Export Module
==================================

Handles exporting captured packet data to various standard formats
for analysis in external tools or archival purposes.

Supported Formats:
    - CSV   : Spreadsheet-compatible, easy to import into Excel or Pandas
    - PCAP  : Standard packet capture format, compatible with Wireshark/tshark
    - JSON  : Structured data format for programmatic access and APIs
    - TXT   : Human-readable summary report with statistics

The PCAP export includes both a Scapy-based exporter (wrpcap) and a
manual binary writer as fallback. The manual writer constructs PCAP
packets by hand using struct.pack() for maximum compatibility.

Usage:
    exporter = PacketExporter()
    exporter.export_csv(packets, "output.csv")
    exporter.export_pcap(packets, "output.pcap")
    exporter.export_json(packets, "output.json")
    exporter.export_summary_report(packets, "report.txt", stats)
"""

import logging
import csv
import json
import struct
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from scapy.all import Raw, Ether, IP, TCP, UDP, ICMP, ARP, DNS, wrpcap
from scapy.utils import PcapWriter

logger = logging.getLogger(__name__)


class PacketExporter:
    """Export captured packets to various formats."""

    # PCAP global header
    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_VERSION_MAJOR = 2
    PCAP_VERSION_MINOR = 4
    PCAP_THISZONE = 0
    PCAP_SIGFIGS = 0
    PCAP_SNAPLEN = 65535
    PCAP_NETWORK = 1  # DLT_EN10MB (Ethernet)

    def __init__(self):
        pass

    def export_csv(self, packets: List[Dict[str, Any]], filepath: str, 
                   fields: List[str] = None) -> int:
        """
        Export packets to CSV format.
        
        Args:
            packets: List of packet dictionaries
            filepath: Output file path
            fields: Specific fields to export (None = all)
            
        Returns:
            Number of packets exported
        """
        if not packets:
            logger.warning("No packets to export")
            return 0

        if fields is None:
            # Default fields for CSV export
            fields = [
                'timestamp_str', 'protocol_name', 'src_mac', 'dst_mac',
                'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'tcp_flags', 'packet_length', 'ip_ttl', 'ip_protocol',
                'dns_query', 'http_method', 'http_host', 'http_status',
                'icmp_type_name', 'arp_op_name', 'is_suspicious', 'threat_type'
            ]

        # Filter packets to only include requested fields
        filtered_packets = []
        for pkt in packets:
            row = {field: pkt.get(field, '') for field in fields}
            # Convert complex types to strings
            for k, v in row.items():
                if isinstance(v, (dict, list)):
                    row[k] = json.dumps(v, default=str)
                elif v is None:
                    row[k] = ''
            filtered_packets.append(row)

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(filtered_packets)
            
            logger.info(f"Exported {len(packets)} packets to CSV: {filepath}")
            return len(packets)
        except Exception as e:
            logger.error(f"CSV export failed: {e}")
            raise

    def export_json(self, packets: List[Dict[str, Any]], filepath: str,
                    pretty: bool = True) -> int:
        """
        Export packets to JSON format.
        
        Args:
            packets: List of packet dictionaries
            filepath: Output file path
            pretty: Whether to pretty-print JSON
            
        Returns:
            Number of packets exported
        """
        if not packets:
            logger.warning("No packets to export")
            return 0

        # Convert packets to JSON-serializable format
        serializable = []
        for pkt in packets:
            serializable.append(self._make_serializable(pkt))

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                if pretty:
                    json.dump(serializable, f, indent=2, default=str)
                else:
                    json.dump(serializable, f, default=str)
            
            logger.info(f"Exported {len(packets)} packets to JSON: {filepath}")
            return len(packets)
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
            raise

    def export_pcap(self, packets: List[Dict[str, Any]], filepath: str) -> int:
        """
        Export packets to PCAP format using Scapy.
        
        Args:
            packets: List of packet dictionaries with raw_data
            filepath: Output file path
            
        Returns:
            Number of packets exported
        """
        if not packets:
            logger.warning("No packets to export")
            return 0

        scapy_packets = []
        for pkt in packets:
            raw_data = pkt.get('raw_data')
            if raw_data:
                try:
                    # Reconstruct packet from raw bytes
                    from scapy.all import Ether
                    scapy_pkt = Ether(raw_data)
                    # Add timestamp
                    if 'timestamp' in pkt:
                        scapy_pkt.time = pkt['timestamp']
                    scapy_packets.append(scapy_pkt)
                except Exception as e:
                    logger.debug(f"Failed to reconstruct packet: {e}")
                    continue

        if not scapy_packets:
            logger.warning("No valid packets for PCAP export")
            return 0

        try:
            wrpcap(filepath, scapy_packets)
            logger.info(f"Exported {len(scapy_packets)} packets to PCAP: {filepath}")
            return len(scapy_packets)
        except Exception as e:
            logger.error(f"PCAP export failed: {e}")
            raise

    def export_pcap_manual(self, packets: List[Dict[str, Any]], filepath: str) -> int:
        """
        Manually write PCAP file (fallback if Scapy wrpcap fails).
        
        Args:
            packets: List of packet dictionaries with raw_data
            filepath: Output file path
            
        Returns:
            Number of packets exported
        """
        count = 0
        try:
            with open(filepath, 'wb') as f:
                # Write global header
                f.write(struct.pack(
                    '<IHHIIII',
                    self.PCAP_MAGIC,
                    self.PCAP_VERSION_MAJOR,
                    self.PCAP_VERSION_MINOR,
                    self.PCAP_THISZONE,
                    self.PCAP_SIGFIGS,
                    self.PCAP_SNAPLEN,
                    self.PCAP_NETWORK
                ))
                
                for pkt in packets:
                    raw_data = pkt.get('raw_data')
                    if not raw_data:
                        continue
                    
                    ts = pkt.get('timestamp', datetime.now().timestamp())
                    ts_sec = int(ts)
                    ts_usec = int((ts - ts_sec) * 1_000_000)
                    pkt_len = len(raw_data)
                    
                    # Write packet header
                    f.write(struct.pack(
                        '<IIII',
                        ts_sec, ts_usec, pkt_len, pkt_len
                    ))
                    
                    # Write packet data
                    f.write(raw_data)
                    count += 1
            
            logger.info(f"Exported {count} packets to PCAP (manual): {filepath}")
            return count
        except Exception as e:
            logger.error(f"Manual PCAP export failed: {e}")
            raise

    def export_summary_report(self, packets: List[Dict[str, Any]], 
                              filepath: str, stats: Dict[str, Any] = None) -> int:
        """
        Export a human-readable summary report.
        
        Args:
            packets: List of packet dictionaries
            filepath: Output file path
            stats: Optional statistics dictionary
            
        Returns:
            Number of packets summarized
        """
        if not packets:
            return 0

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("PACKETVISION PRO - CAPTURE SUMMARY REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"Total Packets: {len(packets)}\n")
                
                if stats:
                    f.write(f"Total Bytes: {stats.get('total_bytes', 0):,}\n")
                    f.write(f"Duration: {stats.get('elapsed_seconds', 0):.1f} seconds\n")
                    f.write(f"Packets/sec: {stats.get('packets_per_second', 0):.2f}\n\n")
                
                # Protocol distribution
                proto_counts = {}
                for pkt in packets:
                    proto = pkt.get('protocol_name', 'Unknown')
                    proto_counts[proto] = proto_counts.get(proto, 0) + 1
                
                f.write("PROTOCOL DISTRIBUTION\n")
                f.write("-" * 40 + "\n")
                for proto, count in sorted(proto_counts.items(), key=lambda x: -x[1]):
                    pct = (count / len(packets)) * 100
                    f.write(f"  {proto:15s}: {count:6d} ({pct:5.1f}%)\n")
                f.write("\n")
                
                # Top talkers
                src_counts = {}
                dst_counts = {}
                for pkt in packets:
                    src = pkt.get('src_ip')
                    dst = pkt.get('dst_ip')
                    if src:
                        src_counts[src] = src_counts.get(src, 0) + 1
                    if dst:
                        dst_counts[dst] = dst_counts.get(dst, 0) + 1
                
                f.write("TOP SOURCE IPs\n")
                f.write("-" * 40 + "\n")
                for ip, count in sorted(src_counts.items(), key=lambda x: -x[1])[:10]:
                    f.write(f"  {ip:15s}: {count}\n")
                f.write("\n")
                
                f.write("TOP DESTINATION IPs\n")
                f.write("-" * 40 + "\n")
                for ip, count in sorted(dst_counts.items(), key=lambda x: -x[1])[:10]:
                    f.write(f"  {ip:15s}: {count}\n")
                f.write("\n")
                
                # Suspicious packets
                suspicious = [p for p in packets if p.get('is_suspicious')]
                if suspicious:
                    f.write(f"SUSPICIOUS PACKETS: {len(suspicious)}\n")
                    f.write("-" * 40 + "\n")
                    for pkt in suspicious[:10]:
                        f.write(f"  [{pkt.get('timestamp_str', '')}] "
                               f"{pkt.get('src_ip')} -> {pkt.get('dst_ip')} "
                               f"({pkt.get('protocol_name')}) "
                               f"Threat: {pkt.get('threat_type', 'Unknown')}\n")
                    if len(suspicious) > 10:
                        f.write(f"  ... and {len(suspicious) - 10} more\n")
                f.write("\n")
                
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            logger.info(f"Exported summary report: {filepath}")
            return len(packets)
        except Exception as e:
            logger.error(f"Summary report export failed: {e}")
            raise

    def _make_serializable(self, obj: Any) -> Any:
        """Convert object to JSON-serializable format."""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._make_serializable(v) for v in obj]
        elif isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        elif isinstance(obj, bytes):
            return obj.hex()
        elif hasattr(obj, '__dict__'):
            return self._make_serializable(obj.__dict__)
        else:
            return str(obj)


class PCAPWriter:
    """Streaming PCAP writer for live capture."""

    def __init__(self, filepath: str, linktype: int = 1):
        self.filepath = filepath
        self.linktype = linktype
        self.file = None
        self.packet_count = 0

    def __enter__(self):
        self.file = open(self.filepath, 'wb')
        # Write global header
        self.file.write(struct.pack(
            '<IHHIIII',
            0xa1b2c3d4,  # magic number
            2, 4,        # version major, minor
            0,           # thiszone
            0,           # sigfigs
            65535,       # snaplen
            self.linktype
        ))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()

    def write_packet(self, packet_data: bytes, timestamp: float = None):
        """Write a packet to the PCAP file."""
        if not self.file:
            raise RuntimeError("PCAP writer not opened")
        
        if timestamp is None:
            timestamp = datetime.now().timestamp()
        
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        pkt_len = len(packet_data)
        
        # Write packet header
        self.file.write(struct.pack('<IIII', ts_sec, ts_usec, pkt_len, pkt_len))
        # Write packet data
        self.file.write(packet_data)
        self.packet_count += 1

    def flush(self):
        """Flush the file buffer."""
        if self.file:
            self.file.flush()


def create_exporter() -> PacketExporter:
    """Factory function to create an exporter."""
    return PacketExporter()


# Convenience functions
def export_to_csv(packets: List[Dict], filepath: str, fields: List[str] = None) -> int:
    """Convenience function to export to CSV."""
    exporter = PacketExporter()
    return exporter.export_csv(packets, filepath, fields)


def export_to_json(packets: List[Dict], filepath: str, pretty: bool = True) -> int:
    """Convenience function to export to JSON."""
    exporter = PacketExporter()
    return exporter.export_json(packets, filepath, pretty)


def export_to_pcap(packets: List[Dict], filepath: str) -> int:
    """Convenience function to export to PCAP."""
    exporter = PacketExporter()
    return exporter.export_pcap(packets, filepath)


def export_summary(packets: List[Dict], filepath: str, stats: Dict = None) -> int:
    """Convenience function to export summary report."""
    exporter = PacketExporter()
    return exporter.export_summary_report(packets, filepath, stats)
