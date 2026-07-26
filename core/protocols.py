"""
PacketVision Pro - Protocol Detection Module
==============================================

Handles parsing and decoding of captured network packets across multiple
protocol layers. Each packet is converted into a dictionary containing
all decoded fields, ready for display in the GUI or storage in the database.

Supported Protocols:
    - Ethernet (Layer 2): Source/Destination MAC, EtherType
    - ARP: Operation type, Sender/Target IP and MAC
    - IPv4/IPv6 (Layer 3): Source/Dest IP, TTL, Protocol, Flags
    - TCP (Layer 4): Ports, Flags (SYN/ACK/FIN/RST), Sequence/Ack numbers, Window
    - UDP (Layer 4): Ports, Length, Checksum
    - ICMP: Type, Code, ID, Sequence
    - DNS: Queries, Answers, Response codes, TTLs
    - HTTP: Method, Path, Host, Headers, Status codes
    - DHCP: Message type and options

The module also includes a MAC vendor lookup table (OUI database) for
identifying device manufacturers from MAC address prefixes.

Typical usage:
    parser = ProtocolParser()
    result = parser.parse_packet(scapy_packet)
    print(result['protocol_name'])  # e.g., "TCP"
    print(result['src_ip'])         # e.g., "192.168.1.100"
"""

import logging
import re
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
    Raw, Padding, RawVal
)
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import ARP as ScapyARP

logger = logging.getLogger(__name__)

# Protocol name mapping
IP_PROTOCOLS = {
    1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE',
    50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP'
}

TCP_FLAGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
}

ICMP_TYPES = {
    0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench',
    5: 'Redirect', 8: 'Echo Request', 11: 'Time Exceeded',
    12: 'Parameter Problem', 13: 'Timestamp Request', 14: 'Timestamp Reply',
    15: 'Information Request', 16: 'Information Reply', 17: 'Address Mask Request',
    18: 'Address Mask Reply', 30: 'Traceroute'
}

ICMP_CODES = {
    3: {0: 'Net Unreachable', 1: 'Host Unreachable', 2: 'Protocol Unreachable',
        3: 'Port Unreachable', 4: 'Fragmentation Needed', 5: 'Source Route Failed',
        6: 'Destination Network Unknown', 7: 'Destination Host Unknown',
        8: 'Source Host Isolated', 9: 'Network Admin Prohibited',
        10: 'Host Admin Prohibited', 11: 'Network Unreachable for TOS',
        12: 'Host Unreachable for TOS', 13: 'Communication Admin Prohibited',
        14: 'Host Precedence Violation', 15: 'Precedence Cutoff'},
    11: {0: 'TTL Expired in Transit', 1: 'Fragment Reassembly Time Exceeded'},
    5: {0: 'Redirect for Network', 1: 'Redirect for Host',
        2: 'Redirect for TOS and Network', 3: 'Redirect for TOS and Host'}
}

ARP_OPERATIONS = {1: 'Request', 2: 'Reply', 3: 'RARP Request', 4: 'RARP Reply'}

DNS_TYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
    15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY'
}

DNS_CLASSES = {1: 'IN', 2: 'CS', 3: 'CH', 4: 'HS'}

WELL_KNOWN_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-SERVER', 68: 'DHCP-CLIENT', 69: 'TFTP',
    80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP', 161: 'SNMP',
    162: 'SNMP-TRAP', 389: 'LDAP', 443: 'HTTPS', 465: 'SMTPS',
    514: 'SYSLOG', 587: 'SMTP-SUBMISSION', 636: 'LDAPS',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'ORACLE',
    3306: 'MYSQL', 3389: 'RDP', 5432: 'POSTGRESQL', 5900: 'VNC',
    6379: 'REDIS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT', 27017: 'MONGODB'
}

# HTTP patterns for detection in raw payload
HTTP_METHODS = {b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', 
                b'PATCH', b'TRACE', b'CONNECT'}
HTTP_VERSIONS = {b'HTTP/1.0', b'HTTP/1.1', b'HTTP/2', b'HTTP/3'}

class ProtocolParser:
    """Main protocol parser class."""

    def __init__(self):
        self.packet_count = 0

    def parse_packet(self, packet) -> Dict[str, Any]:
        """Parse a packet and extract all protocol information."""
        self.packet_count += 1
        
        result = {
            'timestamp': datetime.now().timestamp(),
            'timestamp_str': datetime.now().isoformat(),
            'packet_length': len(packet),
            'protocol_name': 'Unknown',
            'raw_data': bytes(packet) if hasattr(packet, '__bytes__') else None,
        }

        # Ethernet layer
        if Ether in packet:
            eth = packet[Ether]
            result.update(self._parse_ethernet(eth))

        # IPv4 layer
        if IP in packet:
            ip = packet[IP]
            result.update(self._parse_ipv4(ip))
            result['ip_version'] = 4

        # IPv6 layer
        if IPv6 in packet:
            ipv6 = packet[IPv6]
            result.update(self._parse_ipv6(ipv6))
            result['ip_version'] = 6

        # Transport layer
        if TCP in packet:
            tcp = packet[TCP]
            result.update(self._parse_tcp(tcp))
            result['protocol_name'] = 'TCP'
            
            # Check for HTTP
            http_data = self._parse_http(tcp)
            if http_data:
                result.update(http_data)
                result['protocol_name'] = 'HTTP'

        elif UDP in packet:
            udp = packet[UDP]
            result.update(self._parse_udp(udp))
            result['protocol_name'] = 'UDP'
            
            # Check for DNS
            dns_data = self._parse_dns(udp)
            if dns_data:
                result.update(dns_data)
                result['protocol_name'] = 'DNS'
            
            # Check for DHCP
            dhcp_data = self._parse_dhcp(packet)
            if dhcp_data:
                result.update(dhcp_data)

        elif ICMP in packet:
            icmp = packet[ICMP]
            result.update(self._parse_icmp(icmp))
            result['protocol_name'] = 'ICMP'

        # ARP layer
        if ARP in packet:
            arp = packet[ARP]
            result.update(self._parse_arp(arp))
            result['protocol_name'] = 'ARP'

        # Add service names for ports
        self._add_service_names(result)

        return result

    def _parse_ethernet(self, eth) -> Dict[str, Any]:
        """Parse Ethernet layer."""
        src_mac = eth.src.upper() if eth.src else '00:00:00:00:00:00'
        dst_mac = eth.dst.upper() if eth.dst else '00:00:00:00:00:00'
        return {
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'eth_type': f"0x{eth.type:04x}",
        }

    def _parse_ipv4(self, ip) -> Dict[str, Any]:
        """Parse IPv4 layer."""
        proto_name = IP_PROTOCOLS.get(ip.proto, f"IPv4:{ip.proto}")
        return {
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'ip_version': 4,
            'ip_protocol': ip.proto,
            'ip_protocol_name': proto_name,
            'ip_ttl': ip.ttl,
            'ip_length': ip.len,
            'ip_flags': ip.flags,
            'ip_frag': ip.frag,
            'ip_tos': ip.tos,
            'ip_id': ip.id,
        }

    def _parse_ipv6(self, ipv6) -> Dict[str, Any]:
        """Parse IPv6 layer."""
        return {
            'src_ip': ipv6.src,
            'dst_ip': ipv6.dst,
            'ip_version': 6,
            'ip_protocol': ipv6.nh,
            'ip_protocol_name': IP_PROTOCOLS.get(ipv6.nh, f"IPv6:{ipv6.nh}"),
            'ip_ttl': ipv6.hlim,
            'ip_length': ipv6.plen,
            'ip_tc': ipv6.tc,
            'ip_flow': ipv6.fl,
        }

    def _parse_tcp(self, tcp) -> Dict[str, Any]:
        """Parse TCP layer."""
        # TCP flag bitmask values
        FLAG_VALUES = {
            'F': 0x01,  # FIN
            'S': 0x02,  # SYN
            'R': 0x04,  # RST
            'P': 0x08,  # PSH
            'A': 0x10,  # ACK
            'U': 0x20,  # URG
            'E': 0x40,  # ECE
            'C': 0x80,  # CWR
        }
        
        flags = []
        try:
            flags_val = int(tcp.flags)
            for flag_char, flag_name in TCP_FLAGS.items():
                if flags_val & FLAG_VALUES.get(flag_char, 0):
                    flags.append(flag_name)
        except Exception:
            flag_str = str(tcp.flags)
            if flag_str and flag_str != '0':
                flags.append(flag_str)
        
        flag_str = ' '.join(flags) if flags else 'None'
        
        return {
            'src_port': tcp.sport,
            'dst_port': tcp.dport,
            'tcp_flags': flag_str,
            'tcp_flags_raw': str(tcp.flags),
            'tcp_seq': tcp.seq,
            'tcp_ack': tcp.ack,
            'tcp_window': tcp.window,
            'tcp_urgptr': tcp.urgptr,
            'tcp_options': str(tcp.options) if tcp.options else '',
        }

    def _parse_udp(self, udp) -> Dict[str, Any]:
        """Parse UDP layer."""
        return {
            'src_port': udp.sport,
            'dst_port': udp.dport,
            'udp_length': udp.len,
            'udp_checksum': udp.chksum,
        }

    def _parse_icmp(self, icmp) -> Dict[str, Any]:
        """Parse ICMP layer."""
        type_name = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
        code_name = ICMP_CODES.get(icmp.type, {}).get(icmp.code, f"Code {icmp.code}")
        
        return {
            'icmp_type': icmp.type,
            'icmp_type_name': type_name,
            'icmp_code': icmp.code,
            'icmp_code_name': code_name,
            'icmp_checksum': icmp.chksum,
            'icmp_id': getattr(icmp, 'id', None),
            'icmp_seq': getattr(icmp, 'seq', None),
        }

    def _parse_arp(self, arp) -> Dict[str, Any]:
        """Parse ARP layer."""
        op_name = ARP_OPERATIONS.get(arp.op, f"Op {arp.op}")
        
        return {
            'arp_op': arp.op,
            'arp_op_name': op_name,
            'arp_hwsrc': arp.hwsrc.upper() if arp.hwsrc else '00:00:00:00:00:00',
            'arp_hwdst': arp.hwdst.upper() if arp.hwdst else '00:00:00:00:00:00',
            'arp_sender_ip': arp.psrc,
            'arp_target_ip': arp.pdst,
            'src_ip': arp.psrc,
            'dst_ip': arp.pdst,
        }

    def _parse_dns(self, udp) -> Optional[Dict[str, Any]]:
        """Parse DNS layer from UDP payload."""
        if DNS not in udp:
            return None
        
        dns = udp[DNS]
        queries = []
        answers = []
        
        try:
            if dns.qd:
                for q in dns.qd if isinstance(dns.qd, list) else [dns.qd]:
                    qtype = DNS_TYPES.get(q.qtype, f"TYPE{q.qtype}")
                    qclass = DNS_CLASSES.get(q.qclass, f"CLASS{q.qclass}")
                    queries.append({
                        'name': q.qname.decode('utf-8', errors='ignore').rstrip('.'),
                        'type': qtype,
                        'type_num': q.qtype,
                        'class': qclass,
                    })
        except Exception:
            pass
        
        try:
            if dns.an:
                for a in dns.an if isinstance(dns.an, list) else [dns.an]:
                    atype = DNS_TYPES.get(a.type, f"TYPE{a.type}")
                    answers.append({
                        'name': a.rrname.decode('utf-8', errors='ignore').rstrip('.') if a.rrname else '',
                        'type': atype,
                        'type_num': a.type,
                        'ttl': a.ttl,
                        'data': str(a.rdata) if a.rdata else '',
                    })
        except Exception:
            pass
        
        if not queries and not answers:
            return None
        
        # Safely extract flags
        try:
            flags_str = str(dns.flags)
        except Exception:
            flags_str = '0'
        
        try:
            qr_val = bool(dns.qr)
        except Exception:
            qr_val = False
        
        try:
            opcode_val = dns.opcode
        except Exception:
            opcode_val = 0
        
        try:
            rcode_val = dns.rcode
        except Exception:
            rcode_val = 0
        
        return {
            'dns_id': getattr(dns, 'id', 0),
            'dns_flags': flags_str,
            'dns_qr': 'Response' if qr_val else 'Query',
            'dns_opcode': opcode_val,
            'dns_rcode': rcode_val,
            'dns_qdcount': getattr(dns, 'qdcount', len(queries)),
            'dns_ancount': getattr(dns, 'ancount', len(answers)),
            'dns_queries': queries,
            'dns_answers': answers,
            'dns_query': queries[0]['name'] if queries else '',
            'dns_qtype': queries[0]['type_num'] if queries else 0,
        }

    def _parse_dhcp(self, packet) -> Optional[Dict[str, Any]]:
        """Parse DHCP layer."""
        if DHCP not in packet:
            return None
        
        dhcp = packet[DHCP]
        options = {}
        for opt in dhcp.options:
            if isinstance(opt, tuple):
                options[opt[0]] = opt[1]
        
        msg_type = options.get('message-type', 0)
        msg_types = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE',
                     5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'}
        
        return {
            'dhcp_msg_type': msg_type,
            'dhcp_msg_type_name': msg_types.get(msg_type, 'UNKNOWN'),
            'dhcp_options': str(options),
        }

    def _parse_http(self, tcp) -> Optional[Dict[str, Any]]:
        """Parse HTTP layer from TCP payload."""
        if not tcp.payload:
            return None
        
        payload = bytes(tcp.payload)
        if not payload:
            return None
        
        # Check if it looks like HTTP
        first_line = payload.split(b'\r\n')[0] if b'\r\n' in payload else payload
        parts = first_line.split(b' ')
        
        # HTTP Request
        if len(parts) >= 2 and parts[0] in HTTP_METHODS:
            method = parts[0].decode('utf-8', errors='ignore')
            path = parts[1].decode('utf-8', errors='ignore') if len(parts) > 1 else '/'
            version = parts[2].decode('utf-8', errors='ignore') if len(parts) > 2 else 'HTTP/1.1'
            
            headers = {}
            body = b''
            header_end = payload.find(b'\r\n\r\n')
            if header_end != -1:
                header_data = payload[:header_end]
                body = payload[header_end + 4:]
                for line in header_data.split(b'\r\n')[1:]:
                    if b': ' in line:
                        k, v = line.split(b': ', 1)
                        headers[k.decode('utf-8', errors='ignore')] = v.decode('utf-8', errors='ignore')
            
            host = headers.get('Host', '')
            
            return {
                'http_method': method,
                'http_path': path,
                'http_version': version,
                'http_host': host,
                'http_headers': headers,
                'http_body_length': len(body),
            }
        
        # HTTP Response
        if len(parts) >= 2 and parts[0].startswith(b'HTTP/'):
            version = parts[0].decode('utf-8', errors='ignore')
            status = int(parts[1]) if parts[1].isdigit() else 0
            reason = parts[2].decode('utf-8', errors='ignore') if len(parts) > 2 else ''
            
            headers = {}
            body = b''
            header_end = payload.find(b'\r\n\r\n')
            if header_end != -1:
                header_data = payload[:header_end]
                body = payload[header_end + 4:]
                for line in header_data.split(b'\r\n')[1:]:
                    if b': ' in line:
                        k, v = line.split(b': ', 1)
                        headers[k.decode('utf-8', errors='ignore')] = v.decode('utf-8', errors='ignore')
            
            return {
                'http_version': version,
                'http_status': status,
                'http_reason': reason,
                'http_headers': headers,
                'http_body_length': len(body),
            }
        
        return None

    def _add_service_names(self, result: Dict[str, Any]):
        """Add service names for well-known ports."""
        for port_field in ['src_port', 'dst_port']:
            port = result.get(port_field)
            if port and port in WELL_KNOWN_PORTS:
                result[f'{port_field}_service'] = WELL_KNOWN_PORTS[port]

    def get_protocol_display(self, packet_data: Dict[str, Any]) -> str:
        """Get human-readable protocol display string."""
        proto = packet_data.get('protocol_name', 'Unknown')
        
        if proto == 'TCP':
            flags = packet_data.get('tcp_flags', '')
            return f"TCP [{flags}]" if flags != 'None' else 'TCP'
        elif proto == 'UDP':
            return 'UDP'
        elif proto == 'ICMP':
            type_name = packet_data.get('icmp_type_name', '')
            return f"ICMP ({type_name})"
        elif proto == 'ARP':
            op_name = packet_data.get('arp_op_name', '')
            return f"ARP ({op_name})"
        elif proto == 'DNS':
            qr = packet_data.get('dns_qr', '')
            return f"DNS ({qr})"
        elif proto == 'HTTP':
            method = packet_data.get('http_method', '')
            status = packet_data.get('http_status', '')
            if method:
                return f"HTTP {method}"
            elif status:
                return f"HTTP {status}"
            return 'HTTP'
        elif proto in IP_PROTOCOLS.values():
            return proto
        
        return proto


class MACVendorLookup:
    """MAC address vendor lookup using OUI database."""
    
    # Common OUI prefixes (abbreviated for size)
    OUI_DATABASE = {
        '00:00:0C': 'Cisco',
        '00:00:5E': 'IANA',
        '00:01:42': 'Parallels',
        '00:03:FF': 'Microsoft',
        '00:05:69': 'VMware',
        '00:0C:29': 'VMware',
        '00:15:5D': 'Microsoft Hyper-V',
        '00:16:3E': 'Xen',
        '00:1A:4A': 'Apple',
        '00:1B:21': 'Intel',
        '00:1C:42': 'Parallels',
        '00:21:F6': 'Apple',
        '00:22:41': 'Google',
        '00:23:32': 'Apple',
        '00:25:00': 'Apple',
        '00:26:08': 'Apple',
        '00:26:4A': 'Apple',
        '00:26:B0': 'Apple',
        '00:27:10': 'Apple',
        '00:50:56': 'VMware',
        '00:50:F2': 'Microsoft',
        '00:A0:C9': 'Intel',
        '00:E0:4C': 'Realtek',
        '04:5C:06': 'Apple',
        '04:69:F8': 'Apple',
        '04:7D:7B': 'Apple',
        '08:00:27': 'VirtualBox',
        '08:00:69': 'Siemens',
        '0C:4D:E9': 'Apple',
        '10:DD:B1': 'Apple',
        '14:10:9F': 'Apple',
        '18:AF:61': 'Apple',
        '1C:1D:86': 'Apple',
        '28:CF:E9': 'Apple',
        '30:10:B3': 'Apple',
        '34:36:3B': 'Apple',
        '3C:07:54': 'Apple',
        '3C:15:C2': 'Apple',
        '40:A6:D9': 'Apple',
        '44:D8:84': 'Apple',
        '48:4B:AA': 'Apple',
        '48:60:BC': 'Apple',
        '4C:32:75': 'Apple',
        '50:ED:3C': 'Apple',
        '54:26:96': 'Apple',
        '58:55:CA': 'Apple',
        '5C:95:AE': 'Apple',
        '60:03:08': 'Apple',
        '60:F4:45': 'Apple',
        '64:20:0C': 'Apple',
        '68:5B:35': 'Apple',
        '68:96:7B': 'Apple',
        '6C:40:08': 'Apple',
        '70:56:81': 'Apple',
        '74:81:14': 'Apple',
        '78:31:C1': 'Apple',
        '78:4F:43': 'Apple',
        '7C:6D:62': 'Apple',
        '80:00:0B': 'Apple',
        '84:38:35': 'Apple',
        '88:63:DF': 'Apple',
        '8C:85:90': 'Apple',
        '90:3A:E0': 'Apple',
        '90:72:40': 'Apple',
        '94:EB:CD': 'Apple',
        '98:01:A7': 'Apple',
        '98:D6:BB': 'Apple',
        '9C:20:7B': 'Apple',
        'A0:1B:29': 'Apple',
        'A4:5E:60': 'Apple',
        'A8:86:DD': 'Apple',
        'AC:3B:77': 'Apple',
        'AC:BC:32': 'Apple',
        'B0:19:C6': 'Apple',
        'B4:F0:AB': 'Apple',
        'B8:09:8A': 'Apple',
        'B8:8D:12': 'Apple',
        'BC:52:B7': 'Apple',
        'C0:BD:D1': 'Apple',
        'C4:2C:03': 'Apple',
        'C8:69:CD': 'Apple',
        'CC:29:F5': 'Apple',
        'CC:3D:82': 'Apple',
        'D0:23:DB': 'Apple',
        'D4:9A:20': 'Apple',
        'D8:30:62': 'Apple',
        'DC:2B:61': 'Apple',
        'E0:AC:CB': 'Apple',
        'E4:8B:7F': 'Apple',
        'E8:06:88': 'Apple',
        'EC:35:86': 'Apple',
        'F0:18:98': 'Apple',
        'F4:0F:24': 'Apple',
        'F8:1E:DF': 'Apple',
        'FC:25:3F': 'Apple',
        '00:0D:B9': 'Belkin',
        '00:17:3F': 'Belkin',
        '00:22:75': 'Belkin',
        '00:50:DA': 'D-Link',
        '00:0F:B5': 'D-Link',
        '00:1B:11': 'D-Link',
        '00:1C:F0': 'D-Link',
        '00:1E:58': 'D-Link',
        '00:21:91': 'D-Link',
        '00:22:B0': 'D-Link',
        '00:24:01': 'D-Link',
        '00:26:5A': 'D-Link',
        'C8:D3:A3': 'D-Link',
        'E8:94:F6': 'D-Link',
        '00:13:10': 'Linksys',
        '00:14:BF': 'Linksys',
        '00:16:B6': 'Linksys',
        '00:18:39': 'Linksys',
        '00:1C:10': 'Linksys',
        '00:1E:E5': 'Linksys',
        '00:21:29': 'Linksys',
        '00:22:6B': 'Linksys',
        '00:23:69': 'Linksys',
        '00:24:5E': 'Linksys',
        '00:25:9C': 'Linksys',
        '00:0D:88': 'Netgear',
        '00:0F:B5': 'Netgear',
        '00:14:6C': 'Netgear',
        '00:18:4D': 'Netgear',
        '00:1B:2F': 'Netgear',
        '00:1F:33': 'Netgear',
        '00:22:3F': 'Netgear',
        '00:24:B2': 'Netgear',
        '00:26:F2': 'Netgear',
        '28:C6:8E': 'Netgear',
        '00:12:17': 'Asus',
        '00:1A:92': 'Asus',
        '00:1D:60': 'Asus',
        '00:22:15': 'Asus',
        '00:24:8C': 'Asus',
        '08:60:6E': 'Asus',
        '10:7B:44': 'Asus',
        '14:DA:E9': 'Asus',
        '20:CF:30': 'Asus',
        '2C:56:DC': 'Asus',
        '30:5A:3A': 'Asus',
        '38:2C:4A': 'Asus',
        '40:16:7E': 'Asus',
        '50:46:5D': 'Asus',
        '54:04:A6': 'Asus',
        '60:45:CB': 'Asus',
        '70:4D:7B': 'Asus',
        '74:D0:2B': 'Asus',
        '80:1F:02': 'Asus',
        '88:D7:F6': 'Asus',
        '9C:5C:8E': 'Asus',
        'A4:2B:B0': 'Asus',
        'B0:6E:BF': 'Asus',
        'B4:E6:2D': 'Asus',
        'BC:AE:C5': 'Asus',
        'C8:60:00': 'Asus',
        'D4:5D:DF': 'Asus',
        'DC:4A:3E': 'Asus',
        'E0:3F:49': 'Asus',
        'F0:79:59': 'Asus',
        'F4:6D:04': 'Asus',
        'FC:AA:14': 'Asus',
    }

    @classmethod
    def lookup(cls, mac: str) -> str:
        """Lookup vendor from MAC address."""
        if not mac:
            return 'Unknown'
        
        # Normalize MAC
        mac_clean = mac.upper().replace('-', ':')
        parts = mac_clean.split(':')
        if len(parts) < 3:
            return 'Unknown'
        
        oui = ':'.join(parts[:3])
        return cls.OUI_DATABASE.get(oui, 'Unknown')


def parse_packet(packet) -> Dict[str, Any]:
    """Convenience function to parse a packet."""
    parser = ProtocolParser()
    return parser.parse_packet(packet)


def get_protocol_display(packet_data: Dict[str, Any]) -> str:
    """Convenience function to get protocol display."""
    parser = ProtocolParser()
    return parser.get_protocol_display(packet_data)


def lookup_mac_vendor(mac: str) -> str:
    """Convenience function for MAC vendor lookup."""
    return MACVendorLookup.lookup(mac)
