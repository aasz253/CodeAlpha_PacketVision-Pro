#!/usr/bin/env python3
"""
PacketVision Pro - Advanced Network Packet Sniffer & Analyzer
==============================================================

Main entry point for the application. Supports two modes of operation:

    1. GUI Mode (default) - Opens a Tkinter-based dashboard for interactive
       packet capture, analysis, and threat monitoring.

    2. CLI Mode (--cli)   - Headless packet capture for server environments.
       Packets are saved directly to CSV, PCAP, or JSON without a GUI.

Both modes require root privileges on Linux for raw socket access.

Usage:
    sudo python3 main.py                       # Launch GUI
    sudo python3 main.py -i eth0               # GUI on specific interface
    sudo python3 main.py --cli -o capture.csv  # CLI mode, save to CSV
    sudo python3 main.py --cli -f tcp          # CLI mode, TCP only
    sudo python3 main.py --help                # Show all options

Author: PacketVision Pro
License: MIT
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))


def setup_logging(level=logging.INFO, log_file=None):
    """Configure application logging."""
    fmt = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    datefmt = '%H:%M:%S'
    
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt=datefmt,
        handlers=handlers,
    )
    
    # Quiet noisy libraries
    logging.getLogger("scapy").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)


def check_dependencies():
    """Check for required and optional dependencies."""
    required = ['scapy']
    optional = ['customtkinter', 'matplotlib', 'numpy', 'pandas']
    
    missing_required = []
    missing_optional = []
    
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing_required.append(pkg)
    
    for pkg in optional:
        try:
            __import__(pkg)
        except ImportError:
            missing_optional.append(pkg)
    
    if missing_required:
        print(f"[ERROR] Required packages missing: {', '.join(missing_required)}")
        print(f"Install with: pip install {' '.join(missing_required)}")
        return False
    
    if missing_optional:
        print(f"[WARNING] Optional packages missing: {', '.join(missing_optional)}")
        print(f"Some features may be unavailable.")
        print(f"Install with: pip install {' '.join(missing_optional)}")
    
    return True


def run_gui(args):
    """Launch the GUI application."""
    from gui.app import PacketVisionApp
    
    print("=" * 60)
    print("  PacketVision Pro v1.0.0")
    print("  Advanced Network Packet Sniffer & Analyzer")
    print("=" * 60)
    print()
    print("  Starting GUI...")
    print("  Press F5 to start capture, F6 to stop")
    print()
    
    app = PacketVisionApp()
    
    if args.interface:
        from core.capture import PacketCaptureEngine
        interfaces = PacketCaptureEngine.get_interfaces()
        iface_names = [i['name'] for i in interfaces]
        if args.interface in iface_names:
            app.interface_var.set(args.interface)
    
    if args.filter:
        app.capture_filter = args.filter
    
    app.run()


def run_cli(args):
    """Run in CLI mode (headless capture)."""
    from core.capture import PacketCaptureEngine
    from core.protocols import ProtocolParser
    from core.database import PacketDatabase
    from core.detection import ThreatDetector
    from core.export import PacketExporter
    
    logger = logging.getLogger("cli")
    
    interface = args.interface
    if not interface:
        interface = PacketCaptureEngine.get_default_interface()
        logger.info(f"Using default interface: {interface}")
    
    db = PacketDatabase(str(PROJECT_ROOT / "packetvision.db"))
    detector = ThreatDetector(alert_callback=lambda a: logger.warning(f"THREAT: {a.description}"))
    exporter = PacketExporter()
    
    packet_count = [0]
    start_time = __import__('time').time()
    
    def on_packet(pkt_data):
        packet_count[0] += 1
        db.insert_packet(pkt_data)
        detector.process_packet(pkt_data)
        
        if packet_count[0] % 100 == 0:
            elapsed = __import__('time').time() - start_time
            rate = packet_count[0] / elapsed if elapsed > 0 else 0
            logger.info(f"Packets: {packet_count[0]} | Rate: {rate:.0f}/s | "
                       f"Protocol: {pkt_data.get('protocol_name', 'Unknown')}")
    
    def on_stats(stats):
        pass
    
    logger.info(f"Starting capture on {interface}")
    if args.filter:
        logger.info(f"Filter: {args.filter}")
    
    engine = PacketCaptureEngine(
        interface=interface,
        bpf_filter=args.filter,
        packet_callback=on_packet,
        stats_callback=on_stats,
    )
    
    if not engine.start():
        logger.error("Failed to start capture")
        return
    
    logger.info("Capturing... Press Ctrl+C to stop")
    
    try:
        import signal
        def signal_handler(sig, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGINT, signal_handler)
        
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        elapsed = time.time() - start_time
        
        logger.info(f"\nCapture stopped.")
        logger.info(f"Packets captured: {packet_count[0]}")
        logger.info(f"Duration: {elapsed:.1f}s")
        
        if args.output:
            stats = engine.get_stats()
            packets = db.get_packets(limit=100000)
            
            if args.output.endswith('.csv'):
                exporter.export_csv(packets, args.output)
            elif args.output.endswith('.pcap'):
                exporter.export_pcap(packets, args.output)
            elif args.output.endswith('.json'):
                exporter.export_json(packets, args.output)
            else:
                exporter.export_csv(packets, args.output + '.csv')
            
            logger.info(f"Saved to {args.output}")
        
        db_info = db.get_db_info()
        logger.info(f"Database: {db_info['packet_count']} packets, {db_info['size_mb']} MB")


def main():
    parser = argparse.ArgumentParser(
        description="PacketVision Pro - Advanced Network Packet Sniffer & Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main.py                        # Launch GUI
    python main.py --interface eth0       # Capture on specific interface
    python main.py --cli --filter 'tcp'   # CLI capture TCP only
    python main.py --cli -o capture.csv   # CLI capture to CSV
        """
    )
    
    parser.add_argument('--interface', '-i', type=str, default=None,
                       help='Network interface to capture on')
    parser.add_argument('--filter', '-f', type=str, default=None,
                       help='BPF capture filter (e.g., "tcp", "udp port 53")')
    parser.add_argument('--output', '-o', type=str, default=None,
                       help='Output file for CLI mode (.csv, .pcap, .json)')
    parser.add_argument('--cli', action='store_true',
                       help='Run in CLI mode (no GUI)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    parser.add_argument('--version', '-v', action='version',
                       version='PacketVision Pro 1.0.0')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(level=log_level)
    
    logger = logging.getLogger("main")
    logger.info("PacketVision Pro v1.0.0")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check root privileges (platform-aware)
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.warning("PacketVision Pro requires Administrator privileges for packet capture on Windows.")
            logger.warning("Right-click Command Prompt/PowerShell and select 'Run as administrator'.")
            logger.warning("Also ensure Npcap is installed: https://npcap.com/#download")
            if not args.cli:
                logger.warning("Attempting to continue in GUI mode...")
    else:
        if os.geteuid() != 0:
            logger.warning("PacketVision Pro requires root privileges for packet capture.")
            logger.warning("Run with: sudo python3 main.py")
            if not args.cli:
                logger.warning("Attempting to continue in GUI mode...")
    
    # Run
    if args.cli:
        run_cli(args)
    else:
        run_gui(args)


if __name__ == '__main__':
    main()
