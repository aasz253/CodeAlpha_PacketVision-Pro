"""
PacketVision Pro - Threat Detection Module
=============================================

Analyzes captured packet streams in real-time to identify suspicious network
activity and potential security threats. Uses sliding time windows and
rate-based thresholds to detect attack patterns.

Detectable Threats:
    - Port Scanning      : Host contacting many unique ports in short time
    - SYN Flood          : Excessive SYN packets without corresponding SYN-ACKs
    - UDP Flood          : High-rate UDP traffic to a single destination
    - ICMP Flood         : High-rate ICMP echo requests
    - DNS Amplification  : Disproportionately large DNS responses (DDoS vector)
    - HTTP Flood         : Excessive HTTP requests in short period
    - Brute Force        : Repeated failed login attempts on common service ports
    - Data Exfiltration  : Unusually large outbound data transfers
    - Suspicious DNS     : High-entropy domain names (possible DGA/tunneling)

Each threat type has configurable thresholds (see ThresholdConfig class).
Alerts are deduplicated using a cooldown period to prevent alert flooding.

Usage:
    detector = ThreatDetector(alert_callback=my_alert_handler)
    alerts = detector.process_packet(packet_data)
    for alert in alerts:
        print(f"[{alert.severity.value}] {alert.description}")
"""

import logging
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Types of threats detected."""
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"
    DNS_AMPLIFICATION = "dns_amplification"
    HTTP_FLOOD = "http_flood"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    SUSPICIOUS_DNS = "suspicious_dns"
    MALFORMED_PACKET = "malformed_packet"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatAlert:
    """Threat alert data structure."""
    timestamp: float
    timestamp_str: str
    threat_type: ThreatType
    severity: Severity
    source_ip: str
    target_ip: str
    source_port: Optional[int] = None
    target_port: Optional[int] = None
    description: str = ""
    packet_count: int = 1
    details: str = ""
    acknowledged: bool = False


@dataclass
class ConnectionTracker:
    """Tracks connections for anomaly detection."""
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    first_seen: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    synack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    ack_count: int = 0
    unique_ports: set = field(default_factory=set)
    flags_seen: set = field(default_factory=set)


class ThresholdConfig:
    """Configuration for detection thresholds."""
    
    # Port scan detection
    PORT_SCAN_THRESHOLD = 20          # Unique ports contacted in time window
    PORT_SCAN_WINDOW = 10             # Time window in seconds
    PORT_SCAN_MIN_PACKETS = 5         # Minimum packets to consider
    
    # SYN flood detection
    SYN_FLOOD_THRESHOLD = 100         # SYN packets per second
    SYN_FLOOD_WINDOW = 5              # Time window in seconds
    SYN_FLOOD_RATIO = 3               # SYN/(SYN+ACK) ratio threshold
    
    # UDP flood detection
    UDP_FLOOD_THRESHOLD = 1000        # UDP packets per second
    UDP_FLOOD_WINDOW = 5              # Time window in seconds
    
    # ICMP flood detection
    ICMP_FLOOD_THRESHOLD = 500        # ICMP packets per second
    ICMP_FLOOD_WINDOW = 5             # Time window in seconds
    
    # DNS amplification
    DNS_AMPLIFICATION_RATIO = 10      # Response/request size ratio
    DNS_AMPLIFICATION_MIN_RESPONSE = 512  # Minimum response size
    
    # HTTP flood
    HTTP_FLOOD_THRESHOLD = 200        # Requests per second
    HTTP_FLOOD_WINDOW = 10            # Time window in seconds
    
    # Brute force
    BRUTE_FORCE_THRESHOLD = 10        # Failed attempts
    BRUTE_FORCE_WINDOW = 60           # Time window in seconds
    
    # Data exfiltration
    EXFILTRATION_THRESHOLD_MB = 100   # MB transferred in window
    EXFILTRATION_WINDOW = 300         # 5 minutes
    
    # Suspicious DNS
    SUSPICIOUS_DNS_ENTROPY = 3.5      # Entropy threshold
    SUSPICIOUS_DNS_LENGTH = 50        # Subdomain length threshold


class ThreatDetector:
    """Main threat detection engine."""

    def __init__(self, config: ThresholdConfig = None, alert_callback: Callable = None):
        self.config = config or ThresholdConfig()
        self.alert_callback = alert_callback
        self._lock = threading.RLock()
        
        # Tracking structures
        self._connections: Dict[str, ConnectionTracker] = {}
        self._src_ip_stats: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._port_scan_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._syn_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._udp_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._icmp_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._http_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._dns_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._login_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._data_transfer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Alert deduplication
        self._recent_alerts: Dict[str, float] = {}
        self._alert_cooldown = 30  # seconds
        
        # Cleanup interval
        self._last_cleanup = time.time()
        self._cleanup_interval = 60  # seconds

    def process_packet(self, packet_data: Dict[str, Any]) -> List[ThreatAlert]:
        """Process a packet and detect threats."""
        alerts = []
        
        with self._lock:
            self._periodic_cleanup()
            
            # Extract key fields
            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')
            src_port = packet_data.get('src_port')
            dst_port = packet_data.get('dst_port')
            protocol = packet_data.get('protocol_name', 'Unknown')
            tcp_flags = packet_data.get('tcp_flags', '')
            packet_length = packet_data.get('packet_length', 0)
            timestamp = packet_data.get('timestamp', time.time())
            
            if not src_ip or not dst_ip:
                return alerts
            
            # Track connection
            conn_key = f"{src_ip}:{dst_ip}:{dst_port}:{protocol}"
            self._update_connection_tracker(conn_key, src_ip, dst_ip, dst_port, protocol, 
                                           tcp_flags, packet_length, timestamp)
            
            # Detect threats based on protocol
            if protocol == 'TCP':
                alerts.extend(self._detect_tcp_threats(packet_data))
            elif protocol == 'UDP':
                alerts.extend(self._detect_udp_threats(packet_data))
            elif protocol == 'ICMP':
                alerts.extend(self._detect_icmp_threats(packet_data))
            
            # DNS-specific detection
            if packet_data.get('dns_query'):
                alerts.extend(self._detect_dns_threats(packet_data))
            
            # HTTP-specific detection
            if packet_data.get('http_method'):
                alerts.extend(self._detect_http_threats(packet_data))
            
            # Port scan detection (cross-protocol)
            alerts.extend(self._detect_port_scan(src_ip, dst_ip, dst_port, timestamp))
            
            # Data exfiltration detection
            alerts.extend(self._detect_data_exfiltration(src_ip, dst_ip, packet_length, timestamp))
            
            # Brute force detection
            alerts.extend(self._detect_brute_force(packet_data))
        
        # Send alerts via callback
        for alert in alerts:
            if self._should_alert(alert):
                if self.alert_callback:
                    try:
                        self.alert_callback(alert)
                    except Exception as e:
                        logger.error(f"Alert callback error: {e}")
        
        return alerts

    def _update_connection_tracker(self, key: str, src_ip: str, dst_ip: str, 
                                    dst_port: int, protocol: str, tcp_flags: str,
                                    packet_length: int, timestamp: float):
        """Update connection tracker."""
        if key not in self._connections:
            self._connections[key] = ConnectionTracker(
                src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
                protocol=protocol, first_seen=timestamp, last_seen=timestamp
            )
        
        conn = self._connections[key]
        conn.last_seen = timestamp
        conn.packet_count += 1
        conn.byte_count += packet_length
        
        if dst_port:
            conn.unique_ports.add(dst_port)
        
        # Track TCP flags
        if 'SYN' in tcp_flags:
            conn.syn_count += 1
            conn.flags_seen.add('SYN')
        if 'ACK' in tcp_flags and 'SYN' not in tcp_flags:
            conn.synack_count += 1
            conn.flags_seen.add('SYN-ACK')
        if 'FIN' in tcp_flags:
            conn.fin_count += 1
            conn.flags_seen.add('FIN')
        if 'RST' in tcp_flags:
            conn.rst_count += 1
            conn.flags_seen.add('RST')
        if 'ACK' in tcp_flags:
            conn.ack_count += 1
            conn.flags_seen.add('ACK')

    def _detect_tcp_threats(self, packet_data: Dict) -> List[ThreatAlert]:
        """Detect TCP-based threats."""
        alerts = []
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        src_port = packet_data.get('src_port')
        dst_port = packet_data.get('dst_port')
        tcp_flags = packet_data.get('tcp_flags', '')
        timestamp = packet_data.get('timestamp', time.time())
        
        if not all([src_ip, dst_ip]):
            return alerts
        
        # SYN flood detection
        syn_key = f"{src_ip}:{dst_ip}:{dst_port}"
        if 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
            self._syn_tracker[syn_key].append(timestamp)
            alerts.extend(self._check_syn_flood(syn_key, src_ip, dst_ip, dst_port, timestamp))
        
        # Track SYN-ACK for ratio
        if 'SYN' in tcp_flags and 'ACK' in tcp_flags:
            ack_key = f"{dst_ip}:{src_ip}:{src_port}"  # Reverse
            self._syn_tracker[ack_key].append(timestamp)
        
        return alerts

    def _check_syn_flood(self, key: str, src_ip: str, dst_ip: str, 
                         dst_port: int, timestamp: float) -> List[ThreatAlert]:
        """Check for SYN flood."""
        alerts = []
        window_start = timestamp - self.config.SYN_FLOOD_WINDOW
        syn_times = [t for t in self._syn_tracker[key] if t > window_start]
        
        if len(syn_times) >= self.config.SYN_FLOOD_THRESHOLD:
            # Check SYN/(SYN+ACK) ratio
            ack_key = f"{dst_ip}:{src_ip}:{dst_port}"
            ack_times = [t for t in self._syn_tracker.get(ack_key, []) if t > window_start]
            
            total_syn = len(syn_times) + len(ack_times)
            if total_syn > 0:
                ratio = len(syn_times) / total_syn if total_syn > 0 else 0
                if ratio > (self.config.SYN_FLOOD_RATIO / (self.config.SYN_FLOOD_RATIO + 1)):
                    alert = ThreatAlert(
                        timestamp=timestamp,
                        timestamp_str=datetime.fromtimestamp(timestamp).isoformat(),
                        threat_type=ThreatType.SYN_FLOOD,
                        severity=Severity.HIGH,
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        target_port=dst_port,
                        description=f"SYN flood detected from {src_ip} to {dst_ip}:{dst_port} "
                                   f"({len(syn_times)} SYN/s, ratio={ratio:.2f})",
                        packet_count=len(syn_times),
                        details=f"SYN rate: {len(syn_times)/self.config.SYN_FLOOD_WINDOW:.1f}/s, "
                               f"SYN/ACK ratio: {ratio:.2f}"
                    )
                    alerts.append(alert)
        
        return alerts

    def _detect_udp_threats(self, packet_data: Dict) -> List[ThreatAlert]:
        """Detect UDP-based threats."""
        alerts = []
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        timestamp = packet_data.get('timestamp', time.time())
        
        if not all([src_ip, dst_ip]):
            return alerts
        
        # UDP flood detection
        key = f"{src_ip}:{dst_ip}:{dst_port}"
        self._udp_tracker[key].append(timestamp)
        
        window_start = timestamp - self.config.UDP_FLOOD_WINDOW
        udp_count = len([t for t in self._udp_tracker[key] if t > window_start])
        
        if udp_count >= self.config.UDP_FLOOD_THRESHOLD:
            alert = ThreatAlert(
                timestamp=timestamp,
                timestamp_str=datetime.fromtimestamp(timestamp).isoformat(),
                threat_type=ThreatType.UDP_FLOOD,
                severity=Severity.HIGH,
                source_ip=src_ip,
                target_ip=dst_ip,
                target_port=dst_port,
                description=f"UDP flood detected from {src_ip} to {dst_ip}:{dst_port} "
                           f"({udp_count} packets in {self.config.UDP_FLOOD_WINDOW}s)",
                packet_count=udp_count,
                details=f"Rate: {udp_count/self.config.UDP_FLOOD_WINDOW:.1f} packets/s"
            )
            alerts.append(alert)
        
        return alerts

    def _detect_icmp_threats(self, packet_data: Dict) -> List[ThreatAlert]:
        """Detect ICMP-based threats."""
        alerts = []
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        icmp_type = packet_data.get('icmp_type')
        timestamp = packet_data.get('timestamp', time.time())
        
        if not all([src_ip, dst_ip]):
            return alerts
        
        # ICMP flood detection
        key = f"{src_ip}:{dst_ip}"
        self._icmp_tracker[key].append(timestamp)
        
        window_start = timestamp - self.config.ICMP_FLOOD_WINDOW
        icmp_count = len([t for t in self._icmp_tracker[key] if t > window_start])
        
        if icmp_count >= self.config.ICMP_FLOOD_THRESHOLD:
            alert = ThreatAlert(
                timestamp=timestamp,
                timestamp_str=datetime.fromtimestamp(timestamp).isoformat(),
                threat_type=ThreatType.ICMP_FLOOD,
                severity=Severity.MEDIUM,
                source_ip=src_ip,
                target_ip=dst_ip,
                description=f"ICMP flood detected from {src_ip} to {dst_ip} "
                           f"({icmp_count} packets in {self.config.ICMP_FLOOD_WINDOW}s)",
                packet_count=icmp_count,
                details=f"Rate: {icmp_count/self.config.ICMP_FLOOD_WINDOW:.1f} packets/s, "
                       f"Type: {icmp_type}"
            )
            alerts.append(alert)
        
        return alerts

    def _detect_dns_threats(self, packet_data: Dict) -> List[ThreatAlert]:
        """Detect DNS-based threats."""
        alerts = []
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        dns_query = packet_data.get('dns_query', '')
        dns_answers = packet_data.get('dns_answers', [])
        timestamp = packet_data.get('timestamp', time.time())
        
        if not all([src_ip, dst_ip]):
            return alerts
        
        # DNS amplification detection
        if dns_answers and packet_data.get('dns_qr') == 'Response':
            query_size = len(dns_query) + 50  # Approximate query size
            response_size = sum(len(str(a.get('data', ''))) for a in dns_answers) + 100
            
            if response_size > query_size * self.config.DNS_AMPLIFICATION_RATIO:
                alert = ThreatAlert(
                    timestamp=timestamp,
                    timestamp_str=datetime.fromtimestamp(timestamp).isoformat(),
                    threat_type=ThreatType.DNS_AMPLIFICATION,
                    severity=Severity.HIGH,
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    description=f"DNS amplification attack detected: {src_ip} -> {dst_ip} "
                               f"(ratio: {response_size/query_size:.1f}x)",
                    packet_count=1,
                    details=f"Query: {dns_query}, Response size: {response_size} bytes"
                )
                alerts.append(alert)
        
        # Suspicious DNS queries (high entropy, long subdomains)
        if dns_query and packet_data.get('dns_qr') == 'Query':
            entropy = self._calculate_entropy(dns_query)
            subdomain = dns_query.split('.')[0] if '.' in dns_query else dns_query
            
            if entropy > self.config.SUSPICIOUS_DNS_ENTROPY or len(subdomain) > self.config.SUSPICIOUS_DNS_LENGTH:
                alert = ThreatAlert(
                    timestamp=timestamp,
                    timestamp_str=datetime.fromtimestamp(timestamp).isoformat(),
                    threat_type=ThreatType.SUSPICIOUS_DNS,
                    severity=Severity.MEDIUM,
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    description=f"Suspicious DNS query from {src_ip}: {dns_query} "
                               f"(entropy: {entropy:.2f}, length: {len(subdomain)})",
                    packet_count=1,
                    details=f"Entropy: {entropy:.2f}, Subdomain length: {len(subdomain)}"
                )
                alerts.append(alert)
        
        return alerts

    def _detect_http_threats(self, packet_data: Dict) -> List[ThreatAlert]:
        """Detect HTTP-based threats."""
        alerts = []
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        http_method = packet_data.get('http_method')
        timestamp = packet_data.get('timestamp', time.time())
        
        if not all([src_ip, dst_ip, http_method]):
            return alerts
        
        # HTTP flood detection
        key = f"{src_ip}:{dst_ip}"
        self._http_tracker[key].append(timestamp)
        
        window_start = timestamp - self.config.HTTP_FLOOD_WINDOW
        http_count = len([t for t in self._http_tracker[key] if t > window_start])
        
        if http_count >= self.config.HTTP_FLOOD_THRESHOLD:
            alert = ThreatAlert(
                timestamp=timestamp,
                timestamp_str=datetime.fromtimestamp(timestamp).isoformat(),
                threat_type=ThreatType.HTTP_FLOOD,
                severity=Severity.HIGH,
                source_ip=src_ip,
                target_ip=dst_ip,
                description=f"HTTP flood detected from {src_ip} to {dst_ip} "
                           f"({http_count} requests in {self.config.HTTP_FLOOD_WINDOW}s)",
                packet_count=http_count,
                details=f"Rate: {http_count/self.config.HTTP_FLOOD_WINDOW:.1f} req/s, Method: {http_method}"
            )
            alerts.append(alert)
        
        return alerts

    def _detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int, 
                          timestamp: float) -> List[ThreatAlert]:
        """Detect port scanning activity."""
        alerts = []
        
        if not dst_port:
            return alerts
        
        key = f"{src_ip}:{dst_ip}"
        self._port_scan_tracker[key].append((timestamp, dst_port))
        
        window_start = timestamp - self.config.PORT_SCAN_WINDOW
        recent = [(t, p) for t, p in self._port_scan_tracker[key] if t > window_start]
        
        unique_ports = len(set(p for _, p in recent))
        total_packets = len(recent)
        
        if (unique_ports >= self.config.PORT_SCAN_THRESHOLD and 
            total_packets >= self.config.PORT_SCAN_MIN_PACKETS):
            ports = sorted(set(p for _, p in recent))
            alert = ThreatAlert(
                timestamp=timestamp,
                timestamp_str=datetime.fromtimestamp(timestamp).isoformat(),
                threat_type=ThreatType.PORT_SCAN,
                severity=Severity.HIGH if unique_ports > 50 else Severity.MEDIUM,
                source_ip=src_ip,
                target_ip=dst_ip,
                description=f"Port scan detected from {src_ip} to {dst_ip}: "
                           f"{unique_ports} unique ports scanned ({total_packets} packets)",
                packet_count=total_packets,
                details=f"Ports: {ports[:20]}{'...' if len(ports) > 20 else ''}"
            )
            alerts.append(alert)
        
        return alerts

    def _detect_data_exfiltration(self, src_ip: str, dst_ip: str, 
                                   packet_length: int, timestamp: float) -> List[ThreatAlert]:
        """Detect potential data exfiltration."""
        alerts = []
        
        key = f"{src_ip}:{dst_ip}"
        self._data_transfer[key].append((timestamp, packet_length))
        
        window_start = timestamp - self.config.EXFILTRATION_WINDOW
        recent = [(t, b) for t, b in self._data_transfer[key] if t > window_start]
        
        total_bytes = sum(b for _, b in recent)
        total_mb = total_bytes / (1024 * 1024)
        
        if total_mb >= self.config.EXFILTRATION_THRESHOLD_MB:
            alert = ThreatAlert(
                timestamp=timestamp,
                timestamp_str=datetime.fromtimestamp(timestamp).isoformat(),
                threat_type=ThreatType.DATA_EXFILTRATION,
                severity=Severity.CRITICAL,
                source_ip=src_ip,
                target_ip=dst_ip,
                description=f"Large data transfer from {src_ip} to {dst_ip}: "
                           f"{total_mb:.1f} MB in {self.config.EXFILTRATION_WINDOW}s",
                packet_count=len(recent),
                details=f"Total bytes: {total_bytes:,}, Packets: {len(recent)}"
            )
            alerts.append(alert)
        
        return alerts

    def _detect_brute_force(self, packet_data: Dict) -> List[ThreatAlert]:
        """Detect brute force attempts."""
        alerts = []
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        tcp_flags = packet_data.get('tcp_flags', '')
        timestamp = packet_data.get('timestamp', time.time())
        
        if not all([src_ip, dst_ip, dst_port]):
            return alerts
        
        # Track failed connections (RST or no SYN-ACK)
        common_brute_ports = {22, 23, 3389, 5900, 21, 1433, 3306, 5432, 27017}
        
        if dst_port in common_brute_ports:
            key = f"{src_ip}:{dst_ip}:{dst_port}"
            
            # Count RST packets (failed connections) or SYN without response
            if 'RST' in tcp_flags:
                self._login_tracker[key].append(timestamp)
                
                window_start = timestamp - self.config.BRUTE_FORCE_WINDOW
                failed_count = len([t for t in self._login_tracker[key] if t > window_start])
                
                if failed_count >= self.config.BRUTE_FORCE_THRESHOLD:
                    alert = ThreatAlert(
                        timestamp=timestamp,
                        timestamp_str=datetime.fromtimestamp(timestamp).isoformat(),
                        threat_type=ThreatType.BRUTE_FORCE,
                        severity=Severity.HIGH,
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        target_port=dst_port,
                        description=f"Brute force attempt on port {dst_port} from {src_ip} "
                                   f"to {dst_ip} ({failed_count} failed attempts)",
                        packet_count=failed_count,
                        details=f"Window: {self.config.BRUTE_FORCE_WINDOW}s, "
                               f"Threshold: {self.config.BRUTE_FORCE_THRESHOLD}"
                    )
                    alerts.append(alert)
        
        return alerts

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0
        
        from math import log2
        freq = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        length = len(string)
        for count in freq.values():
            p = count / length
            entropy -= p * log2(p)
        
        return entropy

    def _should_alert(self, alert: ThreatAlert) -> bool:
        """Check if alert should be fired (deduplication)."""
        key = f"{alert.threat_type.value}:{alert.source_ip}:{alert.target_ip}:{alert.target_port}"
        now = time.time()
        
        if key in self._recent_alerts:
            if now - self._recent_alerts[key] < self._alert_cooldown:
                return False
        
        self._recent_alerts[key] = now
        return True

    def _periodic_cleanup(self):
        """Clean up old tracking data."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        self._last_cleanup = now
        cutoff = now - 300  # 5 minutes
        
        # Clean connection trackers
        dead_keys = [k for k, v in self._connections.items() if v.last_seen < cutoff]
        for k in dead_keys:
            del self._connections[k]
        
        # Clean other trackers
        for tracker in [self._port_scan_tracker, self._syn_tracker, 
                       self._udp_tracker, self._icmp_tracker, self._http_tracker,
                       self._dns_tracker, self._login_tracker, self._data_transfer]:
            for key in list(tracker.keys()):
                tracker[key] = deque([x for x in tracker[key] if x[0] > cutoff] 
                                   if isinstance(tracker[key], deque) and tracker[key] 
                                   and isinstance(tracker[key][0], tuple) 
                                   else [x for x in tracker[key] if x > cutoff])
                if not tracker[key]:
                    del tracker[key]
        
        # Clean alert deduplication
        for key in list(self._recent_alerts.keys()):
            if now - self._recent_alerts[key] > self._alert_cooldown * 2:
                del self._recent_alerts[key]

    def get_active_threats(self) -> List[Dict[str, Any]]:
        """Get currently active threats."""
        threats = []
        now = time.time()
        
        with self._lock:
            # Active port scans
            for key, scans in self._port_scan_tracker.items():
                recent = [(t, p) for t, p in scans if t > now - 60]
                if recent:
                    unique_ports = len(set(p for _, p in recent))
                    if unique_ports >= self.config.PORT_SCAN_THRESHOLD:
                        src_ip, dst_ip = key.split(':', 1)
                        threats.append({
                            'type': 'port_scan',
                            'source_ip': src_ip,
                            'target_ip': dst_ip,
                            'unique_ports': unique_ports,
                            'packet_count': len(recent),
                            'last_seen': max(t for t, _ in recent),
                        })
            
            # Active SYN floods
            for key, syns in self._syn_tracker.items():
                recent = [t for t in syns if t > now - 30]
                if len(recent) >= self.config.SYN_FLOOD_THRESHOLD:
                    parts = key.split(':')
                    if len(parts) >= 3:
                        threats.append({
                            'type': 'syn_flood',
                            'source_ip': parts[0],
                            'target_ip': parts[1],
                            'target_port': int(parts[2]),
                            'syn_rate': len(recent) / 30,
                            'last_seen': max(recent),
                        })
        
        return threats

    def update_config(self, **kwargs):
        """Update detection thresholds."""
        for key, value in kwargs.items():
            if hasattr(self.config, key.upper()):
                setattr(self.config, key.upper(), value)
                logger.info(f"Updated {key} = {value}")

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        with self._lock:
            return {
                'active_connections': len(self._connections),
                'tracked_sources': len(self._src_ip_stats),
                'port_scan_trackers': len(self._port_scan_tracker),
                'syn_trackers': len(self._syn_tracker),
                'udp_trackers': len(self._udp_tracker),
                'icmp_trackers': len(self._icmp_tracker),
                'http_trackers': len(self._http_tracker),
                'dns_trackers': len(self._dns_tracker),
                'login_trackers': len(self._login_tracker),
                'data_transfer_trackers': len(self._data_transfer),
                'recent_alerts': len(self._recent_alerts),
            }


def create_detector(alert_callback: Callable = None, **config_kwargs) -> ThreatDetector:
    """Factory function to create a threat detector."""
    config = ThresholdConfig()
    for key, value in config_kwargs.items():
        if hasattr(config, key.upper()):
            setattr(config, key.upper(), value)
    return ThreatDetector(config=config, alert_callback=alert_callback)
