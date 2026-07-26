# PacketVision Pro

**Advanced Network Packet Sniffer & Analyzer**

A cybersecurity desktop application built with Python for live network packet capture, protocol analysis, threat detection, and traffic visualization. Designed as a lightweight alternative to Wireshark with a modern, professional interface.

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Technical Details](#technical-details)
- [Dependencies](#dependencies)
- [Known Limitations](#known-limitations)
- [Future Work](#future-work)
- [License](#license)

---

## About

PacketVision Pro is a network security tool developed as part of the CodeAlpha Cyber Security Internship program. It captures live network traffic using Scapy, decodes multiple protocol layers, detects suspicious activity, and presents everything in a clean Tkinter-based dashboard inspired by Wireshark.

The tool is aimed at security analysts and network administrators who need a quick, scriptable packet analyzer with built-in threat detection capabilities.

---

## Features

### Core Functionality
- **Live Packet Capture** - Real-time network traffic capture using Scapy on any available interface
- **Protocol Detection** - Automatic decoding of Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP, and DHCP protocols
- **Packet Statistics** - Real-time counters for packets, bytes, rates, and protocol distribution
- **Traffic Visualization** - Live throughput graphs using Matplotlib (packets/sec and KB/sec)

### Analysis Tools
- **Wireshark-Style Display Filters** - Filter by protocol, IP, port, or custom expressions (e.g., `tcp`, `ip.src == 192.168.1.1`, `tcp.port == 443`, `dns.qry.name == example.com`)
- **Full-Text Search** - Search across all packet fields
- **Protocol Decode View** - Hierarchical protocol tree with field-by-field breakdown
- **Hex Dump Viewer** - Raw packet data in hex + ASCII format
- **MAC Vendor Lookup** - Identify device manufacturers from MAC addresses using OUI database

### Threat Detection
- **Port Scan Detection** - Identifies hosts scanning multiple ports within a time window
- **SYN Flood Detection** - Detects TCP SYN flood attacks using SYN/SYN-ACK ratio analysis
- **UDP/ICMP Flood Detection** - Flags volumetric UDP and ICMP flood attacks
- **DNS Amplification Detection** - Catches DNS response amplification used in DDoS
- **Suspicious DNS Queries** - Flags high-entropy or abnormally long subdomain names (potential C2 communication)
- **HTTP Flood Detection** - Detects HTTP request floods
- **Brute Force Detection** - Monitors common service ports for repeated failed connection attempts
- **Data Exfiltration Detection** - Alerts on unusually large outbound data transfers
- **Alert Severity Levels** - Low, Medium, High, and Critical severity classification

### Export & Storage
- **SQLite Database** - All captured packets stored locally with indexed queries for fast retrieval
- **CSV Export** - Spreadsheet-compatible format for further analysis
- **PCAP Export** - Standard format compatible with Wireshark, tshark, and other tools
- **JSON Export** - Structured data format for programmatic access
- **Summary Report** - Human-readable text report with protocol breakdown and top talkers

### User Interface
- **Dark Mode Dashboard** - Professional Wireshark-inspired color scheme
- **Packet List** - Color-coded by protocol with alternating row backgrounds
- **Tabbed Panels** - Statistics, Alerts, Protocol Distribution, Conversations, and Traffic Graph
- **Context Menu** - Right-click to copy IPs, filter by source/destination, or export
- **Keyboard Shortcuts** - F5 (start), F6 (stop), Space (pause), Ctrl+S/O/E/Q
- **BPF Filter Support** - Berkeley Packet Filter expressions for kernel-level filtering
- **Auto-Scroll** - Toggle for automatic scrolling to latest packets

### CLI Mode
- **Headless Capture** - Run without GUI for server environments
- **Flexible Output** - Save directly to CSV, PCAP, or JSON from command line
- **Real-Time Logging** - Console output with packet counts and rates

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   GUI Layer                      │
│         gui/app.py  •  gui/styles.py            │
│    Tkinter Dashboard • Protocol Tree • Graphs    │
├─────────────────────────────────────────────────┤
│                 Core Logic Layer                 │
│  ┌───────────┐ ┌───────────┐ ┌───────────────┐  │
│  │  capture   │ │ protocols │ │  detection    │  │
│  │  (Scapy)   │ │  (Parser) │ │  (Threats)    │  │
│  └───────────┘ └───────────┘ └───────────────┘  │
│  ┌───────────┐ ┌───────────┐                     │
│  │ database   │ │  export   │                     │
│  │ (SQLite)   │ │(CSV/PCAP) │                     │
│  └───────────┘ └───────────┘                     │
└─────────────────────────────────────────────────┘
```

The application follows a modular architecture where each core component is responsible for a single concern:

- **capture.py** handles packet sniffing via Scapy in a separate thread, invoking callbacks for each captured packet
- **protocols.py** decodes raw packets into structured dictionaries with all protocol fields
- **detection.py** analyzes packet streams for suspicious patterns using sliding time windows
- **database.py** persists all captured data in SQLite with proper indexing
- **export.py** converts internal packet data to standard formats (CSV, PCAP, JSON)
- **gui/app.py** ties everything together in the Tkinter main loop

---

## Installation

PacketVision Pro runs on **Windows**, **Linux** (Ubuntu, Kali, Fedora, etc.), and **macOS**. The only requirement is Python 3.8+ and administrator/root privileges for live packet capture.

### Quick Install (All Platforms)

```bash
# 1. Clone or download the project
git clone https://github.com/yourusername/packetvision-pro.git
cd packetvision-pro

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run (see platform-specific notes below)
sudo python3 main.py            # Linux / macOS
python main.py                  # Windows (run terminal as Administrator)
```

---

### Windows

#### Prerequisites

1. **Python 3.8+** -- Download from [python.org](https://www.python.org/downloads/). During installation, check **"Add Python to PATH"**.

2. **Npcap** -- Required for raw packet capture on Windows. Download and install from [npcap.com](https://npcap.com/#download). During installation, check **"Install in WinPcap API-compatible mode"**.

3. **Administrator privileges** -- Right-click your terminal (Command Prompt, PowerShell, or VS Code) and select **"Run as administrator"**.

#### Install Steps

```powershell
# Open PowerShell as Administrator, then:
cd C:\path\to\packetvision-pro
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Run the application
python main.py
```

#### Windows Notes

- Tkinter is bundled with the standard Python installer on Windows -- no extra install needed.
- BPF capture filters (the `--filter` argument) work fully with Npcap.
- If Scapy fails to detect interfaces, ensure Npcap is installed and the "WinPcap API-compatible mode" option was checked.

---

### Kali Linux / Ubuntu / Debian

#### Prerequisites

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python 3 and pip (usually pre-installed)
sudo apt install -y python3 python3-pip python3-venv

# Install Tkinter (not always included by default on Debian/Ubuntu)
sudo apt install -y python3-tk

# Install libpcap for Scapy's capture backend
sudo apt install -y libpcap-dev
```

#### Install Steps

```bash
cd ~/packetvision-pro
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run (root required for raw sockets)
sudo python3 main.py
```

#### Kali-Specific Notes

- Kali ships with Python 3 and pip pre-installed. Only `python3-tk` and `libpcap-dev` typically need to be installed.
- On Kali, your network interface is usually `wlan0` (Wi-Fi) or `eth0` (wired). The app auto-detects available interfaces.
- For best results on wireless interfaces, put your adapter in **monitor mode** first with `airmon-ng start wlan0`, then select the monitor interface in PacketVision Pro.

---

### Fedora / Red Hat / CentOS

```bash
# Install dependencies
sudo dnf install -y python3 python3-pip python3-tkinter libpcap-devel

# Create venv and install packages
cd ~/packetvision-pro
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run
sudo python3 main.py
```

---

### macOS

#### Prerequisites

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and dependencies
brew install python3 libpcap

# Tkinter comes bundled with the official Python installer.
# If using Homebrew Python, install it separately:
brew install python-tk
```

#### Install Steps

```bash
cd ~/packetvision-pro
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run (root required for raw sockets on macOS)
sudo python3 main.py
```

#### macOS Notes

- macOS uses BPF (Berkeley Packet Filter) for packet capture. Scapy handles this automatically.
- On macOS Ventura+, you may need to grant **Terminal** or **Python** permission under **System Settings > Privacy & Security > Network**.
- Apple Silicon (M1/M2/M3) is fully supported. All dependencies have native ARM64 wheels.

---

### Dependencies Reference

| Package | Purpose | Required | Notes |
|---------|---------|----------|-------|
| `scapy` | Packet capture and protocol dissection | Yes | Core dependency |
| `matplotlib` | Live traffic graphs and visualization | Recommended | Falls back to text stats if missing |
| `numpy` | Numerical operations for graphs | Recommended | Required by matplotlib |
| `pandas` | Data analysis utilities | Optional | Used in some export features |

**System-level dependencies:**

| Platform | Package | Install Command |
|----------|---------|----------------|
| Ubuntu/Debian/Kali | python3-tk | `sudo apt install python3-tk` |
| Ubuntu/Debian/Kali | libpcap-dev | `sudo apt install libpcap-dev` |
| Fedora/RHEL | python3-tkinter | `sudo dnf install python3-tkinter` |
| Fedora/RHEL | libpcap-devel | `sudo dnf install libpcap-devel` |
| macOS | libpcap | `brew install libpcap` |
| Windows | Npcap | [npcap.com](https://npcap.com/#download) |

---

### Platform Compatibility Summary

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| Live packet capture | Full (root required) | Full (Npcap + Admin) | Full (root required) |
| BPF capture filters | Full | Full (with Npcap) | Full |
| Interface auto-detection | Full | Full | Full |
| Protocol parsing | Full | Full | Full |
| Threat detection | Full | Full | Full |
| Traffic graphs | Full | Full | Full |
| SQLite database | Full | Full | Full |
| Export (CSV/PCAP/JSON) | Full | Full | Full |
| Promiscuous mode | Full | Partial | Full |

---

### Troubleshooting

**"No module named tkinter"** (Linux only)
```bash
sudo apt install python3-tk      # Debian/Ubuntu/Kali
sudo dnf install python3-tkinter  # Fedora/RHEL
```

**"No such device" or "Permission denied" when capturing**
```bash
# Make sure you're running as root
sudo python3 main.py

# On Windows, ensure Npcap is installed and terminal is run as Administrator
```

**"No interfaces found"**
- On Windows: Ensure Npcap is installed with WinPcap API-compatible mode.
- On macOS: Grant network permission to your terminal app in System Settings > Privacy & Security > Network.
- On Linux: Ensure your user has access to `/dev/net/` or run as root.

**"No module named scapy"**
```bash
# If using a virtual environment, make sure it's activated
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows
pip install scapy
```

**GUI is too small or fonts are blurry**
- This can happen on high-DPI displays. The app uses Tkinter's default scaling. Adjust your OS display scaling settings if needed.

---

## Usage

### GUI Mode (Default)

```bash
# Launch with default interface
sudo python3 main.py

# Launch on specific interface
sudo python3 main.py -i eth0

# Launch with a capture filter
sudo python3 main.py -f "tcp port 80"
```

### CLI Mode

```bash
# Capture all traffic, save to CSV
sudo python3 main.py --cli -o capture.csv

# Capture only TCP traffic
sudo python3 main.py --cli -f tcp -o tcp_capture.csv

# Capture DNS traffic to PCAP
sudo python3 main.py --cli -f "udp port 53" -o dns_capture.pcap

# Enable debug logging
sudo python3 main.py --cli --debug -o debug_capture.csv
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| F5 | Start capture |
| F6 | Stop capture |
| Space | Pause/Resume capture |
| Ctrl+S | Save packets as CSV |
| Ctrl+O | Open PCAP file |
| Ctrl+E | Export menu |
| Ctrl+Q | Quit application |
| Escape | Clear display filter |

### Display Filter Syntax

The display filter supports Wireshark-like expressions:

```
tcp                          # Show only TCP packets
udp                          # Show only UDP packets
ip.src == 192.168.1.1       # Packets from specific source
ip.dst == 10.0.0.1          # Packets to specific destination
tcp.port == 443             # HTTPS traffic
udp.port == 53              # DNS traffic
dns.qry.name == google.com  # DNS queries for a domain
http.host == example.com    # HTTP traffic to a host
frame.len > 1000            # Large packets
suspicious                   # Flagged packets
```

---

## Project Structure

```
packetvision-pro/
├── main.py                  # Entry point (GUI + CLI modes)
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── LICENSE                  # MIT License
├── .gitignore              # Git ignore rules
│
├── core/                   # Core logic modules
│   ├── __init__.py         # Package metadata
│   ├── protocols.py        # Protocol parsing and decoding
│   ├── capture.py          # Scapy-based packet capture engine
│   ├── database.py         # SQLite storage and retrieval
│   ├── detection.py        # Threat detection engine
│   └── export.py           # CSV, PCAP, JSON export
│
└── gui/                    # User interface
    ├── __init__.py         # Package init
    ├── app.py              # Main application window
    └── styles.py           # Theme and color constants
```

---

## Technical Details

### Protocol Support

| Layer | Protocols | Fields Decoded |
|-------|-----------|----------------|
| Data Link | Ethernet, ARP | MAC addresses, EtherType, ARP operations |
| Network | IPv4, IPv6 | Source/Dest IP, TTL, Protocol, Flags, Fragment offset |
| Transport | TCP, UDP | Ports, Sequence/Ack numbers, Flags, Window size |
| Application | DNS, HTTP, DHCP | Query/Response, Methods, Headers, Status codes |
| ICMP | ICMPv4 | Type, Code, Echo ID/Sequence |

### Threat Detection Algorithms

**Port Scan Detection**
Tracks unique destination ports per source-destination pair within a configurable time window (default: 20 ports in 10 seconds).

**SYN Flood Detection**
Monitors SYN packet rate and calculates the SYN/(SYN+ACK) ratio. A high ratio with high volume indicates a SYN flood.

**DNS Amplification**
Compares DNS response size to query size. A ratio above 10x with responses larger than 512 bytes triggers an alert.

**Suspicious DNS**
Uses Shannon entropy calculation on domain names. High entropy (above 3.5) or unusually long subdomains (above 50 chars) may indicate DGA-based malware or tunneling.

**Brute Force**
Counts RST packets (failed connection attempts) on common service ports (22, 23, 3389, etc.) within a time window.

### Database Schema

The SQLite database contains four tables:
- `packets` - All captured packet metadata and decoded fields (indexed on timestamp, IPs, ports, protocol)
- `alerts` - Security alerts with severity classification
- `statistics` - Periodic statistics snapshots for historical analysis
- `settings` - Application configuration key-value store

---

## Dependencies

```
scapy>=2.5.0
matplotlib>=3.5.0
numpy>=1.21.0
pandas>=1.3.0
```

---

## Known Limitations

- **Root/Admin Required**: Live packet capture requires elevated privileges on all platforms (`sudo` on Linux/macOS, "Run as Administrator" on Windows with Npcap)
- **Encrypted Traffic**: Cannot decrypt TLS/SSL traffic; only sees ciphertext
- **HTTP/2 and HTTP/3**: Limited support for newer HTTP versions over cleartext
- **Performance**: Very high traffic rates (100k+ pps) may cause GUI slowdown due to Tkinter's single-threaded nature
- **Windows Capture**: Some BPF filters and promiscuous mode features may not work on Windows without Npcap
- **MAC Vendor Database**: The built-in OUI database covers common vendors only; can be extended

---

## Future Work

- [ ] Add TLS/SSL certificate extraction and analysis
- [ ] Implement packet replay functionality
- [ ] Add GeoIP lookup for source/destination countries
- [ ] Support for packet reassembly (TCP stream following)
- [ ] Plugin system for custom detection rules
- [ ] Bandwidth usage per host/per protocol over time
- [ ] Alert notification via email/webhook
- [ ] Cross-platform installer (Windows .exe, macOS .app)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Scapy](https://scapy.net/) - Powerful interactive packet manipulation library
- [Wireshark](https://www.wireshark.org/) - Inspiration for the interface design and filter syntax
- [Matplotlib](https://matplotlib.org/) - Visualization library for traffic graphs
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - Python's standard GUI toolkit

---

*Developed as part of the CodeAlpha Cyber Security Internship Program*
