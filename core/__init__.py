"""
PacketVision Pro - Core Package
================================

This package contains the core logic for packet capture, protocol decoding,
threat detection, database storage, and data export.

Modules:
    protocols  - Protocol parsing and decoding for Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP
    capture    - Scapy-based packet capture engine with threading support
    database   - SQLite database for persistent packet storage and retrieval
    detection  - Threat detection engine for identifying suspicious network activity
    export     - Packet export to CSV, PCAP, and JSON formats

Author: PacketVision Pro
License: MIT
"""

__version__ = "1.0.0"
__author__ = "PacketVision Pro"
__license__ = "MIT"
