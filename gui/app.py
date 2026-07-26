"""
PacketVision Pro - Main Application
======================================

Contains the primary GUI class (PacketVisionApp) that builds and manages
the entire user interface. The interface is modeled after Wireshark with
a dark cybersecurity theme and provides:

    - Toolbar with interface selector, capture controls, and filter bar
    - Packet list (Treeview) with color-coded protocol rows
    - Packet detail/decode view with hierarchical protocol tree
    - Tabbed panels for Statistics, Alerts, Protocols, Conversations, and Traffic Graph
    - Right-click context menu for quick filtering and export
    - Keyboard shortcuts for common operations

The GUI runs in the main Tkinter thread while packet capture runs in a
background thread. Captured packets are queued and processed in batches
(50ms intervals) to keep the UI responsive under high traffic.

Classes:
    PacketVisionApp - Main application class (entry point for GUI)

Keyboard Shortcuts:
    F5            Start capture
    F6            Stop capture
    Space         Pause/Resume capture
    Ctrl+S        Save as CSV
    Ctrl+O        Open PCAP file
    Ctrl+E        Export menu
    Ctrl+Q        Quit
    Escape        Clear display filter
"""

import os
import sys
import time
import json
import logging
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from collections import defaultdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.database import PacketDatabase
from core.capture import PacketCaptureEngine, CaptureStats, LiveCaptureManager
from core.protocols import ProtocolParser, MACVendorLookup, WELL_KNOWN_PORTS, DNS_TYPES
from core.detection import ThreatDetector, ThresholdConfig, ThreatAlert, Severity
from core.export import PacketExporter, PCAPWriter
from core.report import generate_report
from gui.styles import DarkTheme, LightTheme, ProtocolColors

logger = logging.getLogger(__name__)

try:
    import matplotlib
    matplotlib.use('TkAgg')
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    logger.warning("matplotlib not available - charts disabled")

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


class PacketVisionApp:
    """Main application class for PacketVision Pro."""

    APP_NAME = "PacketVision Pro"
    APP_VERSION = "1.0.0"
    WINDOW_SIZE = "1400x900"

    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{self.APP_NAME} v{self.APP_VERSION}")
        self.root.geometry(self.WINDOW_SIZE)
        self.root.minsize(1000, 600)
        
        # State
        self.dark_mode = True
        self.theme = DarkTheme
        self.capturing = False
        self.paused = False
        self.packets = []
        self.packet_id_map = {}
        self.selected_packet = None
        self.capture_filter = ""
        self.display_filter = ""
        self.auto_scroll = True
        self.interface = None
        self.db = None
        self.engine = None
        self.detector = None
        self.exporter = PacketExporter()
        self._stats_update_id = None
        self._packet_queue = []
        self._queue_lock = threading.Lock()
        self._processing_queue = False
        self._last_packet_count = 0
        
        # Performance: caps and incremental counters
        self.MAX_PACKETS = 50000
        self.MAX_VISIBLE_ROWS = 5000
        self._inc_total_bytes = 0
        self._inc_suspicious = 0
        self._inc_proto_counts = defaultdict(int)
        self._inc_src_ips = set()
        self._inc_dst_ips = set()
        self._inc_src_ip_counts = defaultdict(int)
        self._inc_dst_ip_counts = defaultdict(int)
        self._inc_conv_counts = defaultdict(lambda: {'count': 0, 'bytes': 0})
        self._capture_start_time = None
        self._alert_history = []
        
        # Initialize components
        self._init_database()
        self._init_detector()
        
        # Build GUI
        self.root.configure(bg=self.theme.BG_PRIMARY)
        self._setup_styles()
        self._build_menubar()
        self._build_toolbar()
        self._build_main_layout()
        self._build_statusbar()
        
        # Bindings
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.bind("<Control-q>", lambda e: self._on_close())
        self.root.bind("<Control-o>", lambda e: self._open_pcap())
        self.root.bind("<Control-s>", lambda e: self._save_csv())
        self.root.bind("<Control-e>", lambda e: self._export_menu())
        self.root.bind("<F5>", lambda e: self._start_capture())
        self.root.bind("<F6>", lambda e: self._stop_capture())
        self.root.bind("<space>", lambda e: self._toggle_pause())
        
        logger.info(f"{self.APP_NAME} initialized")

    def _init_database(self):
        db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "packetvision.db")
        self.db = PacketDatabase(db_path)

    def _init_detector(self):
        self.detector = ThreatDetector(alert_callback=self._on_threat_detected)

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        t = self.theme
        
        # Frame styles
        self.style.configure('Dark.TFrame', background=t.BG_PRIMARY)
        self.style.configure('Card.TFrame', background=t.BG_CARD)
        self.style.configure('Header.TFrame', background=t.BG_HEADER)
        
        # Label styles
        self.style.configure('Dark.TLabel', background=t.BG_PRIMARY, foreground=t.FG_PRIMARY,
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_MD))
        self.style.configure('Title.TLabel', background=t.BG_PRIMARY, foreground=t.FG_BRIGHT,
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_TITLE, 'bold'))
        self.style.configure('Subtitle.TLabel', background=t.BG_PRIMARY, foreground=t.FG_SECONDARY,
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_SM))
        self.style.configure('Stat.TLabel', background=t.BG_CARD, foreground=t.FG_PRIMARY,
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_SM))
        self.style.configure('StatValue.TLabel', background=t.BG_CARD, foreground=t.ACCENT_BLUE,
                            font=(t.FONT_FAMILY, t.FONT_SIZE_LG, 'bold'))
        self.style.configure('Logo.TLabel', background=t.BG_HEADER, foreground=t.ACCENT_BLUE,
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_XL, 'bold'))
        
        # Button styles
        self.style.configure('Dark.TButton', background=t.BG_TERTIARY, foreground=t.FG_PRIMARY,
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_SM), padding=(10, 5))
        self.style.map('Dark.TButton',
                       background=[('active', t.ACCENT_BLUE), ('disabled', t.BG_INPUT)],
                       foreground=[('active', t.FG_BRIGHT)])
        
        self.style.configure('Start.TButton', background=t.ACCENT_GREEN, foreground='#000000',
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_SM, 'bold'), padding=(10, 5))
        self.style.map('Start.TButton',
                       background=[('active', '#00cc6a'), ('disabled', t.BG_INPUT)])
        
        self.style.configure('Stop.TButton', background=t.ACCENT_RED, foreground='#ffffff',
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_SM, 'bold'), padding=(10, 5))
        self.style.map('Stop.TButton',
                       background=[('active', '#cc3333'), ('disabled', t.BG_INPUT)])
        
        self.style.configure('Pause.TButton', background=t.ACCENT_ORANGE, foreground='#000000',
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_SM, 'bold'), padding=(10, 5))
        
        # Entry styles
        self.style.configure('Dark.TEntry', fieldbackground=t.BG_INPUT, foreground=t.FG_PRIMARY,
                            insertcolor=t.FG_PRIMARY, font=(t.FONT_FAMILY, t.FONT_SIZE_SM))
        
        # Combobox styles
        self.style.configure('Dark.TCombobox', fieldbackground=t.BG_INPUT, foreground=t.FG_PRIMARY,
                            background=t.BG_TERTIARY, arrowcolor=t.FG_PRIMARY,
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_SM))
        self.style.map('Dark.TCombobox', fieldbackground=[('readonly', t.BG_INPUT)])
        
        # Treeview styles
        self.style.configure('Dark.Treeview', background=t.BG_SECONDARY, foreground=t.FG_PRIMARY,
                            fieldbackground=t.BG_SECONDARY, borderwidth=0,
                            font=(t.FONT_FAMILY, t.FONT_SIZE_SM),
                            rowheight=t.TREE_ROW_HEIGHT)
        self.style.configure('Dark.Treeview.Heading', background=t.BG_HEADER,
                            foreground=t.FG_PRIMARY, font=(t.FONT_FAMILY_UI, t.FONT_SIZE_SM, 'bold'),
                            relief='flat')
        self.style.map('Dark.Treeview',
                       background=[('selected', t.BG_SELECTED)],
                       foreground=[('selected', t.FG_BRIGHT)])
        self.style.map('Dark.Treeview.Heading',
                       background=[('active', t.BG_TERTIARY)])
        
        # Notebook styles
        self.style.configure('Dark.TNotebook', background=t.BG_PRIMARY, borderwidth=0)
        self.style.configure('Dark.TNotebook.Tab', background=t.BG_SECONDARY,
                            foreground=t.FG_SECONDARY, padding=(12, 6),
                            font=(t.FONT_FAMILY_UI, t.FONT_SIZE_SM))
        self.style.map('Dark.TNotebook.Tab',
                       background=[('selected', t.BG_TERTIARY)],
                       foreground=[('selected', t.FG_BRIGHT)])
        
        # PanedWindow
        self.style.configure('Dark.TPanedwindow', background=t.BG_PRIMARY)
        
        # Scrollbar
        self.style.configure('Dark.Vertical.TScrollbar', background=t.BG_SECONDARY,
                            troughcolor=t.BG_PRIMARY, arrowcolor=t.FG_SECONDARY,
                            borderwidth=0, relief='flat')
        self.style.configure('Dark.Horizontal.TScrollbar', background=t.BG_SECONDARY,
                            troughcolor=t.BG_PRIMARY, arrowcolor=t.FG_SECONDARY,
                            borderwidth=0, relief='flat')
        
        # Separator
        self.style.configure('Dark.TSeparator', background=t.BORDER_COLOR)

    def _build_menubar(self):
        menubar = tk.Menu(self.root, bg=self.theme.BG_HEADER, fg=self.theme.FG_PRIMARY,
                         activebackground=self.theme.ACCENT_BLUE, activeforeground='#ffffff',
                         borderwidth=0)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=self.theme.BG_SECONDARY,
                           fg=self.theme.FG_PRIMARY, activebackground=self.theme.ACCENT_BLUE,
                           activeforeground='#ffffff')
        file_menu.add_command(label="Open PCAP...  Ctrl+O", command=self._open_pcap)
        file_menu.add_command(label="Save Packets CSV...  Ctrl+S", command=self._save_csv)
        file_menu.add_command(label="Export PCAP...", command=self._save_pcap)
        file_menu.add_command(label="Export JSON...", command=self._save_json)
        file_menu.add_command(label="Export Summary Report...", command=self._save_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit  Ctrl+Q", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Capture menu
        capture_menu = tk.Menu(menubar, tearoff=0, bg=self.theme.BG_SECONDARY,
                              fg=self.theme.FG_PRIMARY, activebackground=self.theme.ACCENT_BLUE,
                              activeforeground='#ffffff')
        capture_menu.add_command(label="Start Capture  F5", command=self._start_capture)
        capture_menu.add_command(label="Stop Capture  F6", command=self._stop_capture)
        capture_menu.add_command(label="Pause/Resume  Space", command=self._toggle_pause)
        capture_menu.add_separator()
        capture_menu.add_command(label="Clear Packets", command=self._clear_packets)
        capture_menu.add_separator()
        capture_menu.add_command(label="Set Interface...", command=self._set_interface_dialog)
        capture_menu.add_command(label="Set Filter...", command=self._set_filter_dialog)
        menubar.add_cascade(label="Capture", menu=capture_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg=self.theme.BG_SECONDARY,
                           fg=self.theme.FG_PRIMARY, activebackground=self.theme.ACCENT_BLUE,
                           activeforeground='#ffffff')
        self._auto_scroll_var = tk.BooleanVar(value=True)
        view_menu.add_checkbutton(label="Auto Scroll", variable=self._auto_scroll_var,
                                 command=self._toggle_auto_scroll)
        view_menu.add_separator()
        view_menu.add_command(label="Statistics  Ctrl+T", command=self._show_statistics)
        view_menu.add_command(label="Protocol Breakdown", command=self._show_protocol_breakdown)
        view_menu.add_command(label="Traffic Graph", command=self._show_traffic_graph)
        view_menu.add_separator()
        view_menu.add_command(label="Alerts Panel", command=self._show_alerts_panel)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg=self.theme.BG_SECONDARY,
                            fg=self.theme.FG_PRIMARY, activebackground=self.theme.ACCENT_BLUE,
                            activeforeground='#ffffff')
        tools_menu.add_command(label="DNS Lookup", command=self._dns_lookup)
        tools_menu.add_command(label="MAC Vendor Lookup", command=self._mac_lookup)
        tools_menu.add_command(label="Whois Lookup", command=self._whois_lookup)
        tools_menu.add_separator()
        tools_menu.add_command(label="Detection Settings...", command=self._detection_settings)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=self.theme.BG_SECONDARY,
                           fg=self.theme.FG_PRIMARY, activebackground=self.theme.ACCENT_BLUE,
                           activeforeground='#ffffff')
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        self.menubar = menubar

    def _build_toolbar(self):
        toolbar = tk.Frame(self.root, bg=self.theme.BG_HEADER, height=48)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        toolbar.pack_propagate(False)
        
        # Logo
        logo_frame = tk.Frame(toolbar, bg=self.theme.BG_HEADER)
        logo_frame.pack(side=tk.LEFT, padx=10)
        
        tk.Label(logo_frame, text="◈", font=("Arial", 18),
                bg=self.theme.BG_HEADER, fg=self.theme.ACCENT_BLUE).pack(side=tk.LEFT)
        tk.Label(logo_frame, text=" PacketVision Pro", font=(self.theme.FONT_FAMILY_UI, 14, 'bold'),
                bg=self.theme.BG_HEADER, fg=self.theme.FG_BRIGHT).pack(side=tk.LEFT, padx=(4, 0))
        
        # Separator
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=6)
        
        # Interface selector
        tk.Label(toolbar, text="Interface:", bg=self.theme.BG_HEADER, fg=self.theme.FG_SECONDARY,
                font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM)).pack(side=tk.LEFT, padx=(4, 2))
        
        self.interface_var = tk.StringVar(value="Loading...")
        self.interface_combo = ttk.Combobox(toolbar, textvariable=self.interface_var,
                                           state='readonly', width=15,
                                           style='Dark.TCombobox')
        self.interface_combo.pack(side=tk.LEFT, padx=2)
        self._load_interfaces()
        
        # Separator
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=6)
        
        # Capture controls
        self.start_btn = ttk.Button(toolbar, text="▶ Start", style='Start.TButton',
                                   command=self._start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=3)
        
        self.stop_btn = ttk.Button(toolbar, text="■ Stop", style='Stop.TButton',
                                  command=self._stop_capture, state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=3)
        
        self.pause_btn = ttk.Button(toolbar, text="❚❚ Pause", style='Pause.TButton',
                                   command=self._toggle_pause, state='disabled')
        self.pause_btn.pack(side=tk.LEFT, padx=3)
        
        # Separator
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=6)
        
        # Filter bar
        tk.Label(toolbar, text="Display Filter:", bg=self.theme.BG_HEADER,
                fg=self.theme.FG_SECONDARY,
                font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM)).pack(side=tk.LEFT, padx=(4, 2))
        
        self.filter_var = tk.StringVar()
        self.filter_entry = tk.Entry(toolbar, textvariable=self.filter_var,
                                    bg=self.theme.BG_INPUT, fg=self.theme.ACCENT_BLUE,
                                    insertbackground=self.theme.FG_PRIMARY,
                                    font=(self.theme.FONT_FAMILY, self.theme.FONT_SIZE_SM),
                                    width=30, relief=tk.FLAT, bd=3)
        self.filter_entry.pack(side=tk.LEFT, padx=2, ipady=3)
        self.filter_entry.bind("<Return>", lambda e: self._apply_filter())
        self.filter_entry.bind("<Escape>", lambda e: (self.filter_var.set(""), self._apply_filter()))
        
        filter_btn = ttk.Button(toolbar, text="Apply", style='Dark.TButton',
                               command=self._apply_filter)
        filter_btn.pack(side=tk.LEFT, padx=3)
        
        clear_filter_btn = ttk.Button(toolbar, text="Clear", style='Dark.TButton',
                                     command=lambda: (self.filter_var.set(""), self._apply_filter()))
        clear_filter_btn.pack(side=tk.LEFT, padx=3)
        
        # Right side - search
        right_frame = tk.Frame(toolbar, bg=self.theme.BG_HEADER)
        right_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(right_frame, text="Search:", bg=self.theme.BG_HEADER,
                fg=self.theme.FG_SECONDARY,
                font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM)).pack(side=tk.LEFT, padx=(0, 4))
        
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(right_frame, textvariable=self.search_var,
                                    bg=self.theme.BG_INPUT, fg=self.theme.FG_PRIMARY,
                                    insertbackground=self.theme.FG_PRIMARY,
                                    font=(self.theme.FONT_FAMILY, self.theme.FONT_SIZE_SM),
                                    width=20, relief=tk.FLAT, bd=3)
        self.search_entry.pack(side=tk.LEFT, ipady=3)
        self.search_entry.bind("<Return>", lambda e: self._apply_search())
        
        search_btn = ttk.Button(right_frame, text="Search", style='Dark.TButton',
                               command=self._apply_search)
        search_btn.pack(side=tk.LEFT, padx=3)

    def _build_main_layout(self):
        main_frame = tk.Frame(self.root, bg=self.theme.BG_PRIMARY)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Main paned window (vertical split)
        main_pane = ttk.PanedWindow(main_frame, orient=tk.VERTICAL, style='Dark.TPanedwindow')
        main_pane.pack(fill=tk.BOTH, expand=True)
        
        # Top pane: packet list
        top_frame = tk.Frame(main_frame, bg=self.theme.BG_PRIMARY)
        self._build_packet_list(top_frame)
        main_pane.add(top_frame, weight=3)
        
        # Bottom pane: detail + tabs
        bottom_pane = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL, style='Dark.TPanedwindow')
        
        # Detail view
        detail_frame = tk.Frame(main_frame, bg=self.theme.BG_PRIMARY)
        self._build_detail_view(detail_frame)
        bottom_pane.add(detail_frame, weight=2)
        
        # Tab panel (Statistics, Alerts, Protocol, etc.)
        tab_frame = tk.Frame(main_frame, bg=self.theme.BG_PRIMARY)
        self._build_tab_panel(tab_frame)
        bottom_pane.add(tab_frame, weight=1)
        
        main_pane.add(bottom_pane, weight=2)
        
        self.main_pane = main_pane
        self.bottom_pane = bottom_pane

    def _build_packet_list(self, parent):
        """Build the main packet list (tree view)."""
        # Stats bar
        stats_frame = tk.Frame(parent, bg=self.theme.BG_CARD, height=35)
        stats_frame.pack(fill=tk.X, pady=(0, 2))
        stats_frame.pack_propagate(False)
        
        self.packet_count_label = tk.Label(stats_frame, text="Packets: 0",
                                          bg=self.theme.BG_CARD, fg=self.theme.FG_SECONDARY,
                                          font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM))
        self.packet_count_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.bytes_label = tk.Label(stats_frame, text="Bytes: 0",
                                   bg=self.theme.BG_CARD, fg=self.theme.FG_SECONDARY,
                                   font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM))
        self.bytes_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.rate_label = tk.Label(stats_frame, text="Rate: 0 pkt/s",
                                  bg=self.theme.BG_CARD, fg=self.theme.FG_SECONDARY,
                                  font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM))
        self.rate_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.capture_status_label = tk.Label(stats_frame, text="● Stopped",
                                            bg=self.theme.BG_CARD, fg=self.theme.ACCENT_RED,
                                            font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM, 'bold'))
        self.capture_status_label.pack(side=tk.RIGHT, padx=10, pady=5)
        
        self.suspicious_label = tk.Label(stats_frame, text="",
                                        bg=self.theme.BG_CARD, fg=self.theme.ACCENT_RED,
                                        font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM, 'bold'))
        self.suspicious_label.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # Tree frame
        tree_frame = tk.Frame(parent, bg=self.theme.BG_PRIMARY)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview columns
        columns = ('no', 'time', 'src', 'dst', 'proto', 'length', 'info')
        
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                style='Dark.Treeview', selectmode='browse')
        
        # Column headings
        self.tree.heading('no', text='#', anchor=tk.W)
        self.tree.heading('time', text='Time', anchor=tk.W)
        self.tree.heading('src', text='Source', anchor=tk.W)
        self.tree.heading('dst', text='Destination', anchor=tk.W)
        self.tree.heading('proto', text='Protocol', anchor=tk.W)
        self.tree.heading('length', text='Len', anchor=tk.E)
        self.tree.heading('info', text='Info', anchor=tk.W)
        
        # Column widths
        self.tree.column('no', width=60, minwidth=50)
        self.tree.column('time', width=130, minwidth=100)
        self.tree.column('src', width=160, minwidth=100)
        self.tree.column('dst', width=160, minwidth=100)
        self.tree.column('proto', width=80, minwidth=60)
        self.tree.column('length', width=60, minwidth=40)
        self.tree.column('info', width=400, minwidth=200)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview,
                           style='Dark.Vertical.TScrollbar')
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview,
                           style='Dark.Horizontal.TScrollbar')
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Treeview tags for protocol coloring
        self.tree.tag_configure('tcp', foreground=DarkTheme.TCP_COLOR)
        self.tree.tag_configure('udp', foreground=DarkTheme.UDP_COLOR)
        self.tree.tag_configure('icmp', foreground=DarkTheme.ICMP_COLOR)
        self.tree.tag_configure('arp', foreground=DarkTheme.ARP_COLOR)
        self.tree.tag_configure('dns', foreground=DarkTheme.DNS_COLOR)
        self.tree.tag_configure('http', foreground=DarkTheme.HTTP_COLOR)
        self.tree.tag_configure('https', foreground=DarkTheme.HTTPS_COLOR)
        self.tree.tag_configure('other', foreground=DarkTheme.OTHER_COLOR)
        self.tree.tag_configure('suspicious', foreground=DarkTheme.ACCENT_RED)
        self.tree.tag_configure('even', background='#1a2535')
        self.tree.tag_configure('odd', background=DarkTheme.BG_SECONDARY)
        
        # Bindings
        self.tree.bind('<<TreeviewSelect>>', self._on_packet_select)
        self.tree.bind('<Double-1>', self._on_packet_double_click)
        self.tree.bind('<Button-3>', self._on_right_click)
        
        self.tree_frame = tree_frame

    def _build_detail_view(self, parent):
        """Build packet detail/decode view."""
        # Header
        header = tk.Frame(parent, bg=self.theme.BG_HEADER, height=30)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="Packet Details", bg=self.theme.BG_HEADER,
                fg=self.theme.FG_PRIMARY, font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM, 'bold')
                ).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Tree for protocol tree
        detail_tree_frame = tk.Frame(parent, bg=self.theme.BG_PRIMARY)
        detail_tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.detail_tree = ttk.Treeview(detail_tree_frame, show='tree',
                                       style='Dark.Treeview', selectmode='browse')
        
        dsb = ttk.Scrollbar(detail_tree_frame, orient=tk.VERTICAL,
                           command=self.detail_tree.yview, style='Dark.Vertical.TScrollbar')
        self.detail_tree.configure(yscrollcommand=dsb.set)
        
        self.detail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.detail_tree.tag_configure('layer', foreground=self.theme.ACCENT_BLUE)
        self.detail_tree.tag_configure('field', foreground=self.theme.FG_PRIMARY)
        self.detail_tree.tag_configure('value', foreground=self.theme.ACCENT_GREEN)
        self.detail_tree.tag_configure('warning', foreground=self.theme.ACCENT_ORANGE)

    def _build_tab_panel(self, parent):
        """Build right tab panel with statistics, alerts, etc."""
        self.tab_notebook = ttk.Notebook(parent, style='Dark.TNotebook')
        self.tab_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Statistics tab
        stats_frame = tk.Frame(self.tab_notebook, bg=self.theme.BG_PRIMARY)
        self._build_statistics_tab(stats_frame)
        self.tab_notebook.add(stats_frame, text="  Statistics  ")
        
        # Alerts tab
        alerts_frame = tk.Frame(self.tab_notebook, bg=self.theme.BG_PRIMARY)
        self._build_alerts_tab(alerts_frame)
        self.tab_notebook.add(alerts_frame, text="  Alerts  ")
        
        # Protocol tab
        proto_frame = tk.Frame(self.tab_notebook, bg=self.theme.BG_PRIMARY)
        self._build_protocol_tab(proto_frame)
        self.tab_notebook.add(proto_frame, text="  Protocols  ")
        
        # Conversations tab
        conv_frame = tk.Frame(self.tab_notebook, bg=self.theme.BG_PRIMARY)
        self._build_conversations_tab(conv_frame)
        self.tab_notebook.add(conv_frame, text="  Conversations  ")
        
        # Graph tab
        if HAS_MATPLOTLIB:
            graph_frame = tk.Frame(self.tab_notebook, bg=self.theme.BG_PRIMARY)
            self._build_graph_tab(graph_frame)
            self.tab_notebook.add(graph_frame, text="  Traffic  ")

    def _build_statistics_tab(self, parent):
        """Build statistics display."""
        canvas = tk.Canvas(parent, bg=self.theme.BG_PRIMARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview,
                                 style='Dark.Vertical.TScrollbar')
        
        self.stats_inner = tk.Frame(canvas, bg=self.theme.BG_PRIMARY)
        self.stats_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas.create_window((0, 0), window=self.stats_inner, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initialize stat_labels dict before creating cards
        self.stat_labels = {}
        
        # Stats cards
        self._create_stat_card(self.stats_inner, "Total Packets", "0", "total_packets_value")
        self._create_stat_card(self.stats_inner, "Total Bytes", "0 B", "total_bytes_value")
        self._create_stat_card(self.stats_inner, "Capture Rate", "0 pkt/s", "rate_value")
        self._create_stat_card(self.stats_inner, "TCP", "0", "tcp_value")
        self._create_stat_card(self.stats_inner, "UDP", "0", "udp_value")
        self._create_stat_card(self.stats_inner, "ICMP", "0", "icmp_value")
        self._create_stat_card(self.stats_inner, "DNS", "0", "dns_value")
        self._create_stat_card(self.stats_inner, "HTTP", "0", "http_value")
        self._create_stat_card(self.stats_inner, "ARP", "0", "arp_value")
        self._create_stat_card(self.stats_inner, "Suspicious", "0", "suspicious_value")
        self._create_stat_card(self.stats_inner, "Unique Src IPs", "0", "unique_src_value")
        self._create_stat_card(self.stats_inner, "Unique Dst IPs", "0", "unique_dst_value")
        
        # Top talkers
        tk.Label(self.stats_inner, text="Top Source IPs", bg=self.theme.BG_PRIMARY,
                fg=self.theme.ACCENT_BLUE, font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM, 'bold')
                ).pack(anchor=tk.W, padx=10, pady=(15, 5))
        
        self.top_src_tree = ttk.Treeview(self.stats_inner, columns=('ip', 'count'),
                                        show='headings', height=5, style='Dark.Treeview')
        self.top_src_tree.heading('ip', text='IP Address')
        self.top_src_tree.heading('count', text='Packets')
        self.top_src_tree.column('ip', width=150)
        self.top_src_tree.column('count', width=70)
        self.top_src_tree.pack(fill=tk.X, padx=10, pady=2)
        
        tk.Label(self.stats_inner, text="Top Destination IPs", bg=self.theme.BG_PRIMARY,
                fg=self.theme.ACCENT_BLUE, font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM, 'bold')
                ).pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self.top_dst_tree = ttk.Treeview(self.stats_inner, columns=('ip', 'count'),
                                        show='headings', height=5, style='Dark.Treeview')
        self.top_dst_tree.heading('ip', text='IP Address')
        self.top_dst_tree.heading('count', text='Packets')
        self.top_dst_tree.column('ip', width=150)
        self.top_dst_tree.column('count', width=70)
        self.top_dst_tree.pack(fill=tk.X, padx=10, pady=2)

    def _create_stat_card(self, parent, label, value, key):
        """Create a statistics card widget."""
        card = tk.Frame(parent, bg=self.theme.BG_CARD, relief=tk.FLAT, bd=0)
        card.pack(fill=tk.X, padx=10, pady=3)
        
        inner = tk.Frame(card, bg=self.theme.BG_CARD)
        inner.pack(fill=tk.X, padx=10, pady=6)
        
        lbl = tk.Label(inner, text=label, bg=self.theme.BG_CARD, fg=self.theme.FG_SECONDARY,
                      font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM))
        lbl.pack(side=tk.LEFT)
        
        val = tk.Label(inner, text=value, bg=self.theme.BG_CARD, fg=self.theme.ACCENT_BLUE,
                      font=(self.theme.FONT_FAMILY, self.theme.FONT_SIZE_LG, 'bold'))
        val.pack(side=tk.RIGHT)
        
        self.stat_labels[key] = val

    def _build_alerts_tab(self, parent):
        """Build alerts panel."""
        header = tk.Frame(parent, bg=self.theme.BG_HEADER, height=30)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="Security Alerts", bg=self.theme.BG_HEADER,
                fg=self.theme.ACCENT_RED, font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM, 'bold')
                ).pack(side=tk.LEFT, padx=10, pady=5)
        
        clear_btn = ttk.Button(header, text="Clear", style='Dark.TButton',
                              command=self._clear_alerts)
        clear_btn.pack(side=tk.RIGHT, padx=5, pady=3)
        
        tree_frame = tk.Frame(parent, bg=self.theme.BG_PRIMARY)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.alert_tree = ttk.Treeview(tree_frame, columns=('time', 'type', 'severity', 'info'),
                                      show='headings', style='Dark.Treeview')
        self.alert_tree.heading('time', text='Time')
        self.alert_tree.heading('type', text='Type')
        self.alert_tree.heading('severity', text='Severity')
        self.alert_tree.heading('info', text='Description')
        
        self.alert_tree.column('time', width=80)
        self.alert_tree.column('type', width=100)
        self.alert_tree.column('severity', width=70)
        self.alert_tree.column('info', width=300)
        
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.alert_tree.yview,
                           style='Dark.Vertical.TScrollbar')
        self.alert_tree.configure(yscrollcommand=vsb.set)
        
        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.alert_tree.tag_configure('low', foreground=DarkTheme.SEV_LOW)
        self.alert_tree.tag_configure('medium', foreground=DarkTheme.SEV_MEDIUM)
        self.alert_tree.tag_configure('high', foreground=DarkTheme.SEV_HIGH)
        self.alert_tree.tag_configure('critical', foreground=DarkTheme.SEV_CRITICAL)
        
        self.alert_count = 0

    def _build_protocol_tab(self, parent):
        """Build protocol distribution display."""
        header = tk.Frame(parent, bg=self.theme.BG_HEADER, height=30)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="Protocol Distribution", bg=self.theme.BG_HEADER,
                fg=self.theme.ACCENT_BLUE, font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM, 'bold')
                ).pack(side=tk.LEFT, padx=10, pady=5)
        
        tree_frame = tk.Frame(parent, bg=self.theme.BG_PRIMARY)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.proto_tree = ttk.Treeview(tree_frame, columns=('proto', 'count', 'bytes', 'pct'),
                                      show='headings', style='Dark.Treeview')
        self.proto_tree.heading('proto', text='Protocol')
        self.proto_tree.heading('count', text='Packets')
        self.proto_tree.heading('bytes', text='Bytes')
        self.proto_tree.heading('pct', text='%')
        
        self.proto_tree.column('proto', width=80)
        self.proto_tree.column('count', width=80)
        self.proto_tree.column('bytes', width=100)
        self.proto_tree.column('pct', width=60)
        
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.proto_tree.yview,
                           style='Dark.Vertical.TScrollbar')
        self.proto_tree.configure(yscrollcommand=vsb.set)
        
        self.proto_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_conversations_tab(self, parent):
        """Build conversations display."""
        header = tk.Frame(parent, bg=self.theme.BG_HEADER, height=30)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="Top Conversations", bg=self.theme.BG_HEADER,
                fg=self.theme.ACCENT_PURPLE, font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM, 'bold')
                ).pack(side=tk.LEFT, padx=10, pady=5)
        
        tree_frame = tk.Frame(parent, bg=self.theme.BG_PRIMARY)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.conv_tree = ttk.Treeview(tree_frame,
                                     columns=('src', 'dst', 'count', 'bytes'),
                                     show='headings', style='Dark.Treeview')
        self.conv_tree.heading('src', text='Source')
        self.conv_tree.heading('dst', text='Destination')
        self.conv_tree.heading('count', text='Packets')
        self.conv_tree.heading('bytes', text='Bytes')
        
        self.conv_tree.column('src', width=130)
        self.conv_tree.column('dst', width=130)
        self.conv_tree.column('count', width=70)
        self.conv_tree.column('bytes', width=90)
        
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.conv_tree.yview,
                           style='Dark.Vertical.TScrollbar')
        self.conv_tree.configure(yscrollcommand=vsb.set)
        
        self.conv_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_graph_tab(self, parent):
        """Build traffic graph with matplotlib."""
        self.graph_figure = Figure(figsize=(4, 3), dpi=100, facecolor=self.theme.BG_PRIMARY)
        self.graph_ax = self.graph_figure.add_subplot(111)
        self.graph_ax.set_facecolor(self.theme.BG_SECONDARY)
        self.graph_ax.tick_params(colors=self.theme.FG_SECONDARY, labelsize=8)
        self.graph_figure.tight_layout(pad=2)
        
        self.graph_canvas = FigureCanvasTkAgg(self.graph_figure, parent)
        self.graph_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.graph_data = {'times': [], 'counts': [], 'bytes': []}

    def _build_statusbar(self):
        """Build bottom status bar."""
        statusbar = tk.Frame(self.root, bg=self.theme.BG_HEADER, height=28)
        statusbar.pack(fill=tk.X, side=tk.BOTTOM)
        statusbar.pack_propagate(False)
        
        self.status_label = tk.Label(statusbar, text="Ready",
                                    bg=self.theme.BG_HEADER, fg=self.theme.FG_SECONDARY,
                                    font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM))
        self.status_label.pack(side=tk.LEFT, padx=10, pady=3)
        
        self.db_status_label = tk.Label(statusbar, text="DB: 0 packets",
                                       bg=self.theme.BG_HEADER, fg=self.theme.FG_MUTED,
                                       font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM))
        self.db_status_label.pack(side=tk.RIGHT, padx=10, pady=3)
        
        self.detector_status_label = tk.Label(statusbar, text="Detector: Active",
                                             bg=self.theme.BG_HEADER, fg=self.theme.STATUS_SUCCESS,
                                             font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM))
        self.detector_status_label.pack(side=tk.RIGHT, padx=10, pady=3)

    # ═══════════════════════════════════════════════════════════════
    # CAPTURE CONTROL
    # ═══════════════════════════════════════════════════════════════

    def _start_capture(self):
        if self.capturing:
            self._set_status("Already capturing")
            return
        
        self.interface = self.interface_var.get()
        if not self.interface or self.interface == "Loading...":
            self._set_status("No interface selected")
            return
        
        self.capturing = True
        self.paused = False
        self._capture_start_time = time.time()
        
        self.start_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self.pause_btn.configure(state='normal')
        self.capture_status_label.configure(text="● Capturing", fg=self.theme.ACCENT_GREEN)
        
        bpf_filter = self.capture_filter if self.capture_filter else None
        
        self.engine = PacketCaptureEngine(
            interface=self.interface,
            bpf_filter=bpf_filter,
            packet_callback=self._on_packet_captured,
            stats_callback=self._on_stats_update,
        )
        
        success = self.engine.start()
        if success:
            self._set_status(f"Capturing on {self.interface}")
        else:
            self.capturing = False
            self.start_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')
            self.pause_btn.configure(state='disabled')
            self.capture_status_label.configure(text="● Error", fg=self.theme.ACCENT_RED)
            self._set_status(f"Failed to start capture on {self.interface}")
            self.engine = None

    def _stop_capture(self):
        if not self.capturing:
            return
        
        self.capturing = False
        self.paused = False
        
        if self.engine:
            self.engine.stop()
            self.engine = None
        
        self.start_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')
        self.pause_btn.configure(state='disabled')
        self.capture_status_label.configure(text="● Stopped", fg=self.theme.ACCENT_RED)
        self._set_status(f"Capture stopped. {len(self.packets)} packets captured.")

    def _toggle_pause(self):
        if not self.capturing:
            return
        
        self.paused = not self.paused
        
        if self.engine:
            if self.paused:
                self.engine.pause()
                self.pause_btn.configure(text="▶ Resume")
                self.capture_status_label.configure(text="● Paused", fg=self.theme.ACCENT_ORANGE)
                self._set_status("Capture paused")
            else:
                self.engine.resume()
                self.pause_btn.configure(text="❚❚ Pause")
                self.capture_status_label.configure(text="● Capturing", fg=self.theme.ACCENT_GREEN)
                self._set_status("Capture resumed")

    def _on_packet_captured(self, packet_data: Dict[str, Any]):
        """Handle captured packet from engine thread."""
        with self._queue_lock:
            self._packet_queue.append(packet_data)
        
        if not self._processing_queue:
            self._processing_queue = True
            self.root.after(50, self._process_packet_queue)

    def _process_packet_queue(self):
        """Process queued packets in the main thread."""
        with self._queue_lock:
            queue = self._packet_queue[:]
            self._packet_queue.clear()
        
        if not queue:
            self._processing_queue = False
            return
        
        for pkt in queue:
            self.packets.append(pkt)
            self._update_incremental_counters(pkt)
            packet_id = len(self.packets)
            self._add_packet_to_tree(packet_id, pkt)
            
            # Cap packet list - trim oldest
            if len(self.packets) > self.MAX_PACKETS:
                trim_count = len(self.packets) - self.MAX_PACKETS
                self.packets = self.packets[trim_count:]
                self._rebuild_incremental_counters()
                self._trim_treeview()
            
            # Run threat detection
            try:
                alerts = self.detector.process_packet(pkt)
            except Exception as e:
                logger.error(f"Detection error: {e}")
        
        self._update_quick_stats()
        
        # Update protocol/conversation tabs periodically (every ~2s)
        self._stats_update_counter = getattr(self, '_stats_update_counter', 0) + len(queue)
        if self._stats_update_counter >= 40:
            self._stats_update_counter = 0
            self._update_statistics_tab()
        
        # Schedule next batch
        if self._processing_queue:
            self.root.after(50, self._process_packet_queue)

    def _update_incremental_counters(self, pkt):
        """Update incremental counters with a new packet."""
        self._inc_total_bytes += pkt.get('packet_length', 0)
        
        proto = pkt.get('protocol_name', 'Unknown')
        self._inc_proto_counts[proto] += 1
        
        src_ip = pkt.get('src_ip')
        dst_ip = pkt.get('dst_ip')
        if src_ip:
            self._inc_src_ips.add(src_ip)
            self._inc_src_ip_counts[src_ip] += 1
        if dst_ip:
            self._inc_dst_ips.add(dst_ip)
            self._inc_dst_ip_counts[dst_ip] += 1
        if src_ip and dst_ip:
            key = (src_ip, dst_ip)
            self._inc_conv_counts[key]['count'] += 1
            self._inc_conv_counts[key]['bytes'] += pkt.get('packet_length', 0)
        
        if pkt.get('is_suspicious'):
            self._inc_suspicious += 1

    def _rebuild_incremental_counters(self):
        """Full rebuild of incremental counters (after trimming packets)."""
        self._inc_total_bytes = 0
        self._inc_suspicious = 0
        self._inc_proto_counts = defaultdict(int)
        self._inc_src_ips = set()
        self._inc_dst_ips = set()
        self._inc_src_ip_counts = defaultdict(int)
        self._inc_dst_ip_counts = defaultdict(int)
        self._inc_conv_counts = defaultdict(lambda: {'count': 0, 'bytes': 0})
        
        for pkt in self.packets:
            self._update_incremental_counters(pkt)

    def _trim_treeview(self):
        """Remove oldest rows from treeview when it exceeds MAX_VISIBLE_ROWS."""
        children = self.tree.get_children()
        if len(children) > self.MAX_VISIBLE_ROWS:
            excess = len(children) - self.MAX_VISIBLE_ROWS
            self.tree.delete(*children[:excess])

    def _add_packet_to_tree(self, packet_id: int, pkt: Dict[str, Any]):
        """Add a packet row to the treeview."""
        ts = pkt.get('timestamp_str', '')
        if ts:
            try:
                dt = datetime.fromisoformat(ts)
                ts = dt.strftime('%H:%M:%S.%f')[:-3]
            except Exception:
                ts = ts[:19]
        
        src = pkt.get('src_ip', pkt.get('src_mac', ''))
        dst = pkt.get('dst_ip', pkt.get('dst_mac', ''))
        proto = pkt.get('protocol_name', 'Unknown')
        length = pkt.get('packet_length', 0)
        info = self._get_packet_info(pkt)
        
        tags = []
        proto_lower = proto.lower()
        if proto_lower in ('tcp', 'udp', 'icmp', 'arp', 'dns', 'http'):
            tags.append(proto_lower)
        else:
            tags.append('other')
        
        if pkt.get('is_suspicious'):
            tags.append('suspicious')
        
        # Alternate row colors
        tags.append('even' if packet_id % 2 == 0 else 'odd')
        
        self.tree.insert('', tk.END, iid=str(packet_id),
                        values=(packet_id, ts, src, dst, proto, length, info),
                        tags=tuple(tags))
        
        if self.auto_scroll:
            self.tree.yview_moveto(1.0)

    def _get_packet_info(self, pkt: Dict[str, Any]) -> str:
        """Generate info string for a packet."""
        proto = pkt.get('protocol_name', '')
        
        if proto == 'TCP':
            flags = pkt.get('tcp_flags', '')
            sp = pkt.get('src_port', '')
            dp = pkt.get('dst_port', '')
            service = pkt.get('dst_port_service', pkt.get('src_port_service', ''))
            parts = []
            if sp:
                parts.append(str(sp))
            if dp:
                parts.append(str(dp))
            port_str = f"{sp} → {dp}" if sp and dp else ""
            info = f"{port_str} [{flags}]"
            if service:
                info += f" ({service})"
            return info
        
        elif proto == 'UDP':
            sp = pkt.get('src_port', '')
            dp = pkt.get('dst_port', '')
            service = pkt.get('dst_port_service', pkt.get('src_port_service', ''))
            port_str = f"{sp} → {dp}" if sp and dp else ""
            info = port_str
            if service:
                info += f" ({service})"
            return info
        
        elif proto == 'ICMP':
            type_name = pkt.get('icmp_type_name', '')
            code = pkt.get('icmp_code', '')
            return f"{type_name} (code={code})"
        
        elif proto == 'ARP':
            op = pkt.get('arp_op_name', '')
            sender = pkt.get('arp_sender_ip', '')
            target = pkt.get('arp_target_ip', '')
            return f"{op}: {sender} → {target}"
        
        elif proto == 'DNS':
            qr = pkt.get('dns_qr', '')
            query = pkt.get('dns_query', '')
            qtype = pkt.get('dns_qtype', 0)
            type_str = DNS_TYPES.get(qtype, str(qtype))
            return f"{qr} {query} ({type_str})"
        
        elif proto == 'HTTP':
            method = pkt.get('http_method', '')
            host = pkt.get('http_host', '')
            path = pkt.get('http_path', '')
            status = pkt.get('http_status', '')
            if method:
                return f"{method} {host}{path}"
            elif status:
                return f"HTTP {status}"
            return "HTTP"
        
        return ""

    def _on_packet_select(self, event):
        """Handle packet selection in tree."""
        selection = self.tree.selection()
        if not selection:
            return
        
        packet_id = int(selection[0])
        if packet_id <= len(self.packets):
            self.selected_packet = self.packets[packet_id - 1]
            self._show_packet_detail(self.selected_packet)

    def _on_packet_double_click(self, event):
        """Handle packet double click - show full details."""
        self._on_packet_select(event)
        if self.selected_packet:
            self._show_packet_window(self.selected_packet)

    def _on_right_click(self, event):
        """Show context menu."""
        selection = self.tree.selection()
        if not selection:
            return
        
        context_menu = tk.Menu(self.root, tearoff=0, bg=self.theme.BG_SECONDARY,
                              fg=self.theme.FG_PRIMARY, activebackground=self.theme.ACCENT_BLUE,
                              activeforeground='#ffffff')
        context_menu.add_command(label="Copy IP", command=self._copy_ip)
        context_menu.add_command(label="Copy MAC", command=self._copy_mac)
        context_menu.add_separator()
        context_menu.add_command(label="Filter by Source IP", command=self._filter_by_src_ip)
        context_menu.add_command(label="Filter by Destination IP", command=self._filter_by_dst_ip)
        context_menu.add_command(label="Filter by Protocol", command=self._filter_by_protocol)
        context_menu.add_separator()
        context_menu.add_command(label="View Packet Details", command=lambda: self._show_packet_window(self.selected_packet))
        context_menu.add_separator()
        context_menu.add_command(label="Export Packet...", command=self._export_selected)
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()

    # ═══════════════════════════════════════════════════════════════
    # PACKET DETAIL VIEW
    # ═══════════════════════════════════════════════════════════════

    def _show_packet_detail(self, pkt: Dict[str, Any]):
        """Show decoded packet in detail tree."""
        for item in self.detail_tree.get_children():
            self.detail_tree.delete(item)
        
        if not pkt:
            return
        
        # Frame / Ethernet
        src_mac = pkt.get('src_mac', 'N/A')
        dst_mac = pkt.get('dst_mac', 'N/A')
        eth_type = pkt.get('eth_type', 'N/A')
        
        mac_vendor_src = MACVendorLookup.lookup(src_mac)
        mac_vendor_dst = MACVendorLookup.lookup(dst_mac)
        
        eth_node = self.detail_tree.insert('', tk.END, text='▶ Frame / Ethernet',
                                          tags=('layer',))
        self.detail_tree.insert(eth_node, tk.END, text=f'Source MAC: {src_mac} ({mac_vendor_src})',
                               tags=('field',))
        self.detail_tree.insert(eth_node, tk.END, text=f'Dest MAC: {dst_mac} ({mac_vendor_dst})',
                               tags=('field',))
        self.detail_tree.insert(eth_node, tk.END, text=f'EtherType: {eth_type}', tags=('field',))
        self.detail_tree.insert(eth_node, tk.END, text=f'Length: {pkt.get("packet_length", 0)} bytes',
                               tags=('field',))
        
        # IP Layer
        if pkt.get('src_ip'):
            src_ip = pkt.get('src_ip', 'N/A')
            dst_ip = pkt.get('dst_ip', 'N/A')
            ip_ver = pkt.get('ip_version', 4)
            ttl = pkt.get('ip_ttl', 'N/A')
            proto = pkt.get('ip_protocol', 'N/A')
            ip_len = pkt.get('ip_length', 'N/A')
            
            ip_node = self.detail_tree.insert('', tk.END, text=f'▶ IPv{ip_ver}',
                                             tags=('layer',))
            self.detail_tree.insert(ip_node, tk.END, text=f'Source IP: {src_ip}',
                                   tags=('field',))
            self.detail_tree.insert(ip_node, tk.END, text=f'Destination IP: {dst_ip}',
                                   tags=('field',))
            self.detail_tree.insert(ip_node, tk.END, text=f'TTL: {ttl}', tags=('field',))
            self.detail_tree.insert(ip_node, tk.END, text=f'Protocol: {proto}',
                                   tags=('field',))
            self.detail_tree.insert(ip_node, tk.END, text=f'IP Length: {ip_len}',
                                   tags=('field',))
        
        # TCP Layer
        if pkt.get('protocol_name') == 'TCP':
            flags = pkt.get('tcp_flags', 'None')
            sp = pkt.get('src_port', '')
            dp = pkt.get('dst_port', '')
            seq = pkt.get('tcp_seq', '')
            ack = pkt.get('tcp_ack', '')
            window = pkt.get('tcp_window', '')
            
            tcp_node = self.detail_tree.insert('', tk.END,
                                              text=f'▶ TCP {sp} → {dp}',
                                              tags=('layer',))
            self.detail_tree.insert(tcp_node, tk.END, text=f'Flags: [{flags}]',
                                   tags=('warning' if 'SYN' in flags else 'field',))
            self.detail_tree.insert(tcp_node, tk.END, text=f'Sequence: {seq}',
                                   tags=('field',))
            self.detail_tree.insert(tcp_node, tk.END, text=f'Acknowledgment: {ack}',
                                   tags=('field',))
            self.detail_tree.insert(tcp_node, tk.END, text=f'Window: {window}',
                                   tags=('field',))
            
            svc = pkt.get('dst_port_service', pkt.get('src_port_service', ''))
            if svc:
                self.detail_tree.insert(tcp_node, tk.END, text=f'Service: {svc}',
                                       tags=('value',))
            
            # HTTP sub-layer
            if pkt.get('http_method') or pkt.get('http_status'):
                http_node = self.detail_tree.insert(tcp_node, text='▶ HTTP',
                                                   tags=('layer',))
                if pkt.get('http_method'):
                    self.detail_tree.insert(http_node, tk.END,
                                           text=f'Method: {pkt["http_method"]}',
                                           tags=('field',))
                    self.detail_tree.insert(http_node, tk.END,
                                           text=f'Host: {pkt.get("http_host", "")}',
                                           tags=('field',))
                    self.detail_tree.insert(http_node, tk.END,
                                           text=f'Path: {pkt.get("http_path", "/")}',
                                           tags=('field',))
                    self.detail_tree.insert(http_node, tk.END,
                                           text=f'Version: {pkt.get("http_version", "HTTP/1.1")}',
                                           tags=('field',))
                if pkt.get('http_status'):
                    self.detail_tree.insert(http_node, tk.END,
                                           text=f'Status: {pkt["http_status"]}',
                                           tags=('value',))
        
        # UDP Layer
        elif pkt.get('protocol_name') == 'UDP':
            sp = pkt.get('src_port', '')
            dp = pkt.get('dst_port', '')
            
            udp_node = self.detail_tree.insert('', tk.END,
                                              text=f'▶ UDP {sp} → {dp}',
                                              tags=('layer',))
            self.detail_tree.insert(udp_node, tk.END, text=f'Length: {pkt.get("udp_length", "")}',
                                   tags=('field',))
            
            # DNS sub-layer
            if pkt.get('dns_query'):
                dns_node = self.detail_tree.insert(udp_node, text='▶ DNS',
                                                   tags=('layer',))
                self.detail_tree.insert(dns_node, tk.END,
                                       text=f'{pkt.get("dns_qr", "Query")} {pkt.get("dns_query", "")}',
                                       tags=('value',))
                if pkt.get('dns_answers'):
                    for ans in pkt['dns_answers'][:5]:
                        self.detail_tree.insert(dns_node, tk.END,
                                               text=f'  Answer: {ans.get("name", "")} → {ans.get("data", "")}',
                                               tags=('field',))
        
        # ICMP Layer
        elif pkt.get('protocol_name') == 'ICMP':
            icmp_node = self.detail_tree.insert('', tk.END, text='▶ ICMP',
                                               tags=('layer',))
            self.detail_tree.insert(icmp_node, tk.END,
                                   text=f'Type: {pkt.get("icmp_type_name", "N/A")}',
                                   tags=('field',))
            self.detail_tree.insert(icmp_node, tk.END,
                                   text=f'Code: {pkt.get("icmp_code_name", "N/A")}',
                                   tags=('field',))
        
        # ARP Layer
        elif pkt.get('protocol_name') == 'ARP':
            arp_node = self.detail_tree.insert('', tk.END, text='▶ ARP',
                                              tags=('layer',))
            self.detail_tree.insert(arp_node, tk.END,
                                   text=f'Operation: {pkt.get("arp_op_name", "N/A")}',
                                   tags=('field',))
            self.detail_tree.insert(arp_node, tk.END,
                                   text=f'Sender: {pkt.get("arp_sender_ip", "")} '
                                        f'({pkt.get("arp_hwsrc", "")})',
                                   tags=('field',))
            self.detail_tree.insert(arp_node, tk.END,
                                   text=f'Target: {pkt.get("arp_target_ip", "")} '
                                        f'({pkt.get("arp_hwdst", "")})',
                                   tags=('field',))
        
        # Threat info
        if pkt.get('is_suspicious'):
            threat_node = self.detail_tree.insert('', tk.END, text='⚠ THREAT DETECTED',
                                                 tags=('layer',))
            self.detail_tree.insert(threat_node, tk.END,
                                   text=f'Type: {pkt.get("threat_type", "Unknown")}',
                                   tags=('warning',))
            if pkt.get('threat_details'):
                self.detail_tree.insert(threat_node, tk.END,
                                       text=f'Details: {pkt["threat_details"]}',
                                       tags=('warning',))

    def _show_packet_window(self, pkt: Dict[str, Any]):
        """Show packet in a separate window with hex dump."""
        if not pkt:
            return
        
        win = tk.Toplevel(self.root)
        win.title(f"Packet #{self.packets.index(pkt) + 1 if pkt in self.packets else '?'}")
        win.geometry("800x600")
        win.configure(bg=self.theme.BG_PRIMARY)
        
        # Protocol tree
        tree_frame = tk.Frame(win, bg=self.theme.BG_PRIMARY)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        tree = ttk.Treeview(tree_frame, show='tree', style='Dark.Treeview')
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Copy detail tree contents
        for item in self.detail_tree.get_children():
            values = self.detail_tree.item(item, 'values')
            text = self.detail_tree.item(item, 'text')
            tags = self.detail_tree.item(item, 'tags')
            new_item = tree.insert('', tk.END, text=text, tags=tags)
            for child in self.detail_tree.get_children(item):
                c_text = self.detail_tree.item(child, 'text')
                c_tags = self.detail_tree.item(child, 'tags')
                tree.insert(new_item, tk.END, text=c_text, tags=c_tags)
        
        tree.tag_configure('layer', foreground=self.theme.ACCENT_BLUE)
        tree.tag_configure('field', foreground=self.theme.FG_PRIMARY)
        tree.tag_configure('value', foreground=self.theme.ACCENT_GREEN)
        tree.tag_configure('warning', foreground=self.theme.ACCENT_ORANGE)
        
        # Hex dump
        raw = pkt.get('raw_data')
        if raw:
            hex_frame = tk.Frame(win, bg=self.theme.BG_SECONDARY)
            hex_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            tk.Label(hex_frame, text="Hex Dump", bg=self.theme.BG_SECONDARY,
                    fg=self.theme.ACCENT_BLUE,
                    font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM, 'bold')
                    ).pack(anchor=tk.W, padx=5, pady=2)
            
            hex_text = scrolledtext.ScrolledText(hex_frame, bg='#0a0a1a',
                                                fg=self.theme.FG_PRIMARY,
                                                insertbackground=self.theme.FG_PRIMARY,
                                                font=(self.theme.FONT_FAMILY, self.theme.FONT_SIZE_SM),
                                                height=15, wrap=tk.NONE)
            hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
            
            hex_str = self._hexdump(raw)
            hex_text.insert(tk.END, hex_str)
            hex_text.config(state=tk.DISABLED)
        
        # Close button
        tk.Button(win, text="Close", command=win.destroy,
                 bg=self.theme.BG_TERTIARY, fg=self.theme.FG_PRIMARY,
                 font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_SM),
                 relief=tk.FLAT, padx=20, pady=5).pack(pady=5)

    def _hexdump(self, data: bytes, bytes_per_line: int = 16) -> str:
        """Generate hex dump of data."""
        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<{bytes_per_line * 3 - 1}}  {ascii_part}')
        return '\n'.join(lines)

    # ═══════════════════════════════════════════════════════════════
    # STATISTICS & UPDATES
    # ═══════════════════════════════════════════════════════════════

    def _update_quick_stats(self):
        """Update quick packet count and bytes using O(1) incremental counters."""
        count = len(self.packets)
        
        self.packet_count_label.config(text=f"Packets: {count}")
        self.bytes_label.config(text=f"Bytes: {self._format_bytes(self._inc_total_bytes)}")
        
        if self._inc_suspicious > 0:
            self.suspicious_label.config(text=f"⚠ {self._inc_suspicious} Suspicious")
        
        self.db_status_label.config(text=f"DB: {count} packets")

    def _on_stats_update(self, stats: Dict[str, Any]):
        """Update UI with capture statistics from engine."""
        pps = stats.get('packets_per_second', 0)
        self.rate_label.config(text=f"Rate: {pps:.0f} pkt/s")
        
        # Update stat labels
        if hasattr(self, 'stat_labels'):
            for key, label in self.stat_labels.items():
                if key in stats:
                    label.config(text=str(stats[key]))
            
            if 'total_bytes' in stats:
                self.stat_labels.get('total_bytes_value', None) and \
                    self.stat_labels['total_bytes_value'].config(
                        text=self._format_bytes(stats['total_bytes']))
            
            if 'packets_per_second' in stats:
                self.stat_labels.get('rate_value', None) and \
                    self.stat_labels['rate_value'].config(
                        text=f"{stats['packets_per_second']:.1f} pkt/s")
        
        # Update graph
        if HAS_MATPLOTLIB and hasattr(self, 'graph_data'):
            now = datetime.now()
            self.graph_data['times'].append(now)
            self.graph_data['counts'].append(pps)
            self.graph_data['bytes'].append(stats.get('bytes_per_second', 0))
            
            if len(self.graph_data['times']) > 100:
                self.graph_data['times'] = self.graph_data['times'][-100:]
                self.graph_data['counts'] = self.graph_data['counts'][-100:]
                self.graph_data['bytes'] = self.graph_data['bytes'][-100:]
            
            self._update_graph()

    def _update_statistics_tab(self):
        """Update the statistics tab using O(1) incremental counters."""
        if not self.packets:
            return
        
        total = len(self.packets)
        self.stat_labels['total_packets_value'].config(text=str(total))
        self.stat_labels['total_bytes_value'].config(text=self._format_bytes(self._inc_total_bytes))
        
        for proto, key in [('TCP', 'tcp_value'), ('UDP', 'udp_value'), ('ICMP', 'icmp_value'),
                           ('DNS', 'dns_value'), ('HTTP', 'http_value'), ('ARP', 'arp_value')]:
            self.stat_labels[key].config(text=str(self._inc_proto_counts.get(proto, 0)))
        
        self.stat_labels['suspicious_value'].config(text=str(self._inc_suspicious))
        self.stat_labels['unique_src_value'].config(text=str(len(self._inc_src_ips)))
        self.stat_labels['unique_dst_value'].config(text=str(len(self._inc_dst_ips)))
        
        # Top src IPs
        for item in self.top_src_tree.get_children():
            self.top_src_tree.delete(item)
        for ip, count in sorted(self._inc_src_ip_counts.items(), key=lambda x: -x[1])[:10]:
            self.top_src_tree.insert('', tk.END, values=(ip, count))
        
        # Top dst IPs
        for item in self.top_dst_tree.get_children():
            self.top_dst_tree.delete(item)
        for ip, count in sorted(self._inc_dst_ip_counts.items(), key=lambda x: -x[1])[:10]:
            self.top_dst_tree.insert('', tk.END, values=(ip, count))
        
        # Protocol distribution
        for item in self.proto_tree.get_children():
            self.proto_tree.delete(item)
        for proto, count in sorted(self._inc_proto_counts.items(), key=lambda x: -x[1]):
            pct = (count / total * 100) if total > 0 else 0
            self.proto_tree.insert('', tk.END, values=(proto, count, '', f'{pct:.1f}%'))
        
        # Conversations
        for item in self.conv_tree.get_children():
            self.conv_tree.delete(item)
        for (src, dst), data in sorted(self._inc_conv_counts.items(), key=lambda x: -x[1]['count'])[:20]:
            self.conv_tree.insert('', tk.END,
                                 values=(src, dst, data['count'], self._format_bytes(data['bytes'])))

    def _update_graph(self):
        """Update traffic graph."""
        if not HAS_MATPLOTLIB or not hasattr(self, 'graph_ax'):
            return
        
        self.graph_ax.clear()
        self.graph_ax.set_facecolor(self.theme.BG_SECONDARY)
        
        if len(self.graph_data['times']) > 1:
            self.graph_ax.plot(self.graph_data['times'], self.graph_data['counts'],
                             color=self.theme.ACCENT_BLUE, linewidth=1.5, label='Packets/s')
            
            ax2 = self.graph_ax.twinx()
            bytes_kb = [b / 1024 for b in self.graph_data['bytes']]
            ax2.plot(self.graph_data['times'], bytes_kb,
                    color=self.theme.ACCENT_GREEN, linewidth=1.0, alpha=0.7, label='KB/s')
            ax2.set_ylabel('KB/s', color=self.theme.FG_SECONDARY, fontsize=8)
            ax2.tick_params(colors=self.theme.FG_SECONDARY, labelsize=8)
        
        self.graph_ax.set_xlabel('Time', color=self.theme.FG_SECONDARY, fontsize=8)
        self.graph_ax.set_ylabel('Packets/s', color=self.theme.FG_SECONDARY, fontsize=8)
        self.graph_ax.tick_params(colors=self.theme.FG_SECONDARY, labelsize=8)
        self.graph_ax.set_title('Traffic Overview', color=self.theme.FG_PRIMARY, fontsize=10)
        self.graph_ax.spines['top'].set_visible(False)
        self.graph_ax.spines['right'].set_visible(False)
        self.graph_ax.spines['bottom'].set_color(self.theme.BORDER_COLOR)
        self.graph_ax.spines['left'].set_color(self.theme.BORDER_COLOR)
        
        self.graph_figure.tight_layout(pad=1.5)
        self.graph_canvas.draw()

    # ═══════════════════════════════════════════════════════════════
    # ALERTS
    # ═══════════════════════════════════════════════════════════════

    def _on_threat_detected(self, alert: ThreatAlert):
        """Handle threat detection alert from detector thread."""
        self.root.after(0, lambda: self._add_alert(alert))
        try:
            self.db.insert_alert({
                'timestamp': alert.timestamp,
                'timestamp_str': alert.timestamp_str,
                'alert_type': alert.threat_type.value,
                'severity': alert.severity.value,
                'src_ip': alert.source_ip,
                'dst_ip': alert.target_ip,
                'src_port': alert.source_port,
                'dst_port': alert.target_port,
                'description': alert.description,
                'packet_count': alert.packet_count,
                'details': alert.details,
            })
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")

    def _add_alert(self, alert: ThreatAlert):
        """Add alert to alerts tree."""
        self.alert_count += 1
        ts = datetime.fromtimestamp(alert.timestamp).strftime('%H:%M:%S')
        
        self._alert_history.append({
            'timestamp_str': ts,
            'alert_type': alert.threat_type.value,
            'severity': alert.severity.value,
            'src_ip': alert.source_ip,
            'dst_ip': alert.target_ip,
            'description': alert.description,
        })
        
        sev = alert.severity.value
        self.alert_tree.insert('', 0,
                             values=(ts, alert.threat_type.value.upper(), sev.upper(),
                                    alert.description),
                             tags=(sev,))
        
        # Mark only the most recent packet from the alert source as suspicious
        # (not ALL packets from that IP, which inflates the count)
        for pkt in reversed(self.packets):
            if pkt.get('src_ip') == alert.source_ip and not pkt.get('is_suspicious'):
                pkt['is_suspicious'] = 1
                pkt['threat_type'] = alert.threat_type.value
                self._inc_suspicious += 1
                break
        
        self.detector_status_label.config(
            text=f"Alerts: {self.alert_count}",
            fg=self.theme.ACCENT_RED if self.alert_count > 0 else self.theme.STATUS_SUCCESS
        )

    def _clear_alerts(self):
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        self.alert_count = 0
        self.detector_status_label.config(text="Detector: Active", fg=self.theme.STATUS_SUCCESS)

    # ═══════════════════════════════════════════════════════════════
    # FILTERING & SEARCH
    # ═══════════════════════════════════════════════════════════════

    def _apply_filter(self):
        """Apply display filter."""
        self.display_filter = self.filter_var.get().strip()
        self._refresh_packet_list()

    def _apply_search(self):
        """Search packets."""
        query = self.search_var.get().strip().lower()
        if not query:
            self._refresh_packet_list()
            return
        
        # Clear tree and re-add matching packets
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for i, pkt in enumerate(self.packets):
            if self._packet_matches_search(pkt, query):
                self._add_packet_to_tree(i + 1, pkt)
        
        self._set_status(f"Search: showing {len(self.tree.get_children())} matches for '{query}'")

    def _packet_matches_search(self, pkt: Dict, query: str) -> bool:
        """Check if packet matches search query."""
        searchable = ' '.join(str(v) for v in pkt.values() if v).lower()
        return query in searchable

    def _packet_matches_filter(self, pkt: Dict, filter_str: str) -> bool:
        """Check if packet matches filter expression."""
        if not filter_str:
            return True
        
        f = filter_str.lower()
        
        proto_map = {
            'tcp': 'TCP', 'udp': 'UDP', 'icmp': 'ICMP', 'arp': 'ARP',
            'dns': 'DNS', 'http': 'HTTP', 'https': 'HTTP'
        }
        
        for key, proto in proto_map.items():
            if f == key:
                return pkt.get('protocol_name') == proto
            if f.startswith(f'{key} ') or f.startswith(f'{key}('):
                return pkt.get('protocol_name') == proto
        
        if f.startswith('ip.src == '):
            ip = f.replace('ip.src == ', '').strip().strip("'\"")
            return pkt.get('src_ip') == ip
        if f.startswith('ip.dst == '):
            ip = f.replace('ip.dst == ', '').strip().strip("'\"")
            return pkt.get('dst_ip') == ip
        if f.startswith('ip.addr == '):
            ip = f.replace('ip.addr == ', '').strip().strip("'\"")
            return pkt.get('src_ip') == ip or pkt.get('dst_ip') == ip
        if f.startswith('ip.host == '):
            host = f.replace('ip.host == ', '').strip().strip("'\"")
            return host in (pkt.get('src_ip', ''), pkt.get('dst_ip', ''), pkt.get('http_host', ''))
        if f.startswith('tcp.port == '):
            port = int(f.replace('tcp.port == ', '').strip())
            return pkt.get('src_port') == port or pkt.get('dst_port') == port
        if f.startswith('udp.port == '):
            port = int(f.replace('udp.port == ', '').strip())
            return pkt.get('src_port') == port or pkt.get('dst_port') == port
        if f.startswith('tcp.srcport == '):
            port = int(f.replace('tcp.srcport == ', '').strip())
            return pkt.get('src_port') == port
        if f.startswith('tcp.dstport == '):
            port = int(f.replace('tcp.dstport == ', '').strip())
            return pkt.get('dst_port') == port
        if f.startswith('dns.qry.name == '):
            name = f.replace('dns.qry.name == ', '').strip().strip("'\"")
            return pkt.get('dns_query', '') == name
        if f.startswith('http.host == '):
            host = f.replace('http.host == ', '').strip().strip("'\"")
            return pkt.get('http_host', '') == host
        if f.startswith('frame.len < '):
            threshold = int(f.replace('frame.len < ', '').strip())
            return pkt.get('packet_length', 0) < threshold
        if f.startswith('frame.len > '):
            threshold = int(f.replace('frame.len > ', '').strip())
            return pkt.get('packet_length', 0) > threshold
        if f == 'suspicious' or f == 'threat':
            return pkt.get('is_suspicious')
        if f.startswith('suspicious == ') or f.startswith('threat.type == '):
            ttype = f.split('==')[-1].strip().strip("'\"")
            return pkt.get('threat_type') == ttype
        
        # Fallback: text search
        return self._packet_matches_search(pkt, f)

    def _refresh_packet_list(self):
        """Refresh packet list with current filter."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for i, pkt in enumerate(self.packets):
            if self._packet_matches_filter(pkt, self.display_filter):
                self._add_packet_to_tree(i + 1, pkt)
        
        count = len(self.tree.get_children())
        self._set_status(f"Showing {count} of {len(self.packets)} packets")

    def _set_filter_from_context(self, filter_str: str):
        """Set filter and apply."""
        self.filter_var.set(filter_str)
        self._apply_filter()

    def _filter_by_src_ip(self):
        if self.selected_packet:
            ip = self.selected_packet.get('src_ip', '')
            self._set_filter_from_context(f"ip.src == {ip}")

    def _filter_by_dst_ip(self):
        if self.selected_packet:
            ip = self.selected_packet.get('dst_ip', '')
            self._set_filter_from_context(f"ip.dst == {ip}")

    def _filter_by_protocol(self):
        if self.selected_packet:
            proto = self.selected_packet.get('protocol_name', '')
            self._set_filter_from_context(proto.lower())

    def _copy_ip(self):
        if self.selected_packet:
            ip = self.selected_packet.get('src_ip', '')
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    def _copy_mac(self):
        if self.selected_packet:
            mac = self.selected_packet.get('src_mac', '')
            self.root.clipboard_clear()
            self.root.clipboard_append(mac)

    # ═══════════════════════════════════════════════════════════════
    # FILE OPERATIONS
    # ═══════════════════════════════════════════════════════════════

    def _open_pcap(self):
        filepath = filedialog.askopenfilename(
            title="Open PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if not filepath:
            return
        
        self._set_status(f"Loading {filepath}...")
        
        def load_pcap():
            try:
                from scapy.all import rdpcap
                raw_packets = rdpcap(filepath)
                
                from core.protocols import ProtocolParser
                parser = ProtocolParser()
                
                for pkt in raw_packets:
                    try:
                        data = parser.parse_packet(pkt)
                        self.packets.append(data)
                    except Exception as e:
                        logger.debug(f"Failed to parse packet: {e}")
                
                self.root.after(0, self._on_pcap_loaded, filepath, len(raw_packets))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load PCAP:\n{e}"))
                self.root.after(0, lambda: self._set_status("Failed to load PCAP"))
        
        threading.Thread(target=load_pcap, daemon=True).start()

    def _on_pcap_loaded(self, filepath, count):
        """Handle PCAP load completion."""
        self._set_status(f"Loaded {count} packets from {Path(filepath).name}")
        self._refresh_packet_list()
        self._update_statistics_tab()
        self._update_quick_stats()

    def _save_csv(self):
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to export")
            return
        
        filepath = filedialog.asksaveasfilename(
            title="Save as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if not filepath:
            return
        
        try:
            count = self.exporter.export_csv(self.packets, filepath)
            self._set_status(f"Exported {count} packets to CSV")
            messagebox.showinfo("Export Complete", f"Exported {count} packets to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _save_pcap(self):
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to export")
            return
        
        filepath = filedialog.asksaveasfilename(
            title="Save as PCAP",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")],
            initialfile=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        )
        if not filepath:
            return
        
        try:
            count = self.exporter.export_pcap(self.packets, filepath)
            if count == 0:
                count = self.exporter.export_pcap_manual(self.packets, filepath)
            self._set_status(f"Exported {count} packets to PCAP")
            messagebox.showinfo("Export Complete", f"Exported {count} packets to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _save_json(self):
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to export")
            return
        
        filepath = filedialog.asksaveasfilename(
            title="Save as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if not filepath:
            return
        
        try:
            count = self.exporter.export_json(self.packets, filepath)
            self._set_status(f"Exported {count} packets to JSON")
            messagebox.showinfo("Export Complete", f"Exported {count} packets to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _save_report(self):
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to export")
            return
        
        filepath = filedialog.asksaveasfilename(
            title="Save Summary Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if not filepath:
            return
        
        try:
            stats = self.engine.get_stats() if self.engine else {}
            count = self.exporter.export_summary_report(self.packets, filepath, stats)
            self._set_status(f"Summary report saved: {filepath}")
            messagebox.showinfo("Report Complete", f"Summary report saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Report Error", str(e))

    def _export_selected(self):
        if not self.selected_packet:
            return
        self._save_csv()

    def _export_menu(self):
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to export")
            return
        
        export_win = tk.Toplevel(self.root)
        export_win.title("Export Packets")
        export_win.geometry("400x250")
        export_win.configure(bg=self.theme.BG_PRIMARY)
        export_win.transient(self.root)
        export_win.grab_set()
        
        tk.Label(export_win, text="Export Format", bg=self.theme.BG_PRIMARY,
                fg=self.theme.FG_PRIMARY, font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_LG, 'bold')
                ).pack(pady=20)
        
        formats = [
            ("CSV (Comma-Separated Values)", self._save_csv),
            ("PCAP (Packet Capture)", self._save_pcap),
            ("JSON (JavaScript Object Notation)", self._save_json),
            ("Summary Report (Text)", self._save_report),
        ]
        
        for label, cmd in formats:
            btn = tk.Button(export_win, text=label, command=lambda c=cmd: (c(), export_win.destroy()),
                          bg=self.theme.BG_TERTIARY, fg=self.theme.FG_PRIMARY,
                          font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_MD),
                          relief=tk.FLAT, width=35, pady=8)
            btn.pack(pady=3)

    # ═══════════════════════════════════════════════════════════════
    # DIALOGS
    # ═══════════════════════════════════════════════════════════════

    def _set_interface_dialog(self):
        self._load_interfaces()

    def _set_filter_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Set Capture Filter (BPF)")
        dialog.geometry("450x200")
        dialog.configure(bg=self.theme.BG_PRIMARY)
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="BPF Capture Filter:", bg=self.theme.BG_PRIMARY,
                fg=self.theme.FG_PRIMARY, font=(self.theme.FONT_FAMILY_UI, self.theme.FONT_SIZE_MD)
                ).pack(pady=(20, 5))
        
        tk.Label(dialog, text="Examples: tcp, udp port 53, host 192.168.1.1",
                bg=self.theme.BG_PRIMARY, fg=self.theme.FG_MUTED,
                font=(self.theme.FONT_FAMILY_UI, 10)).pack(pady=(0, 5))
        
        filter_var = tk.StringVar(value=self.capture_filter)
        entry = tk.Entry(dialog, textvariable=filter_var,
                        bg=self.theme.BG_INPUT, fg=self.theme.ACCENT_BLUE,
                        insertbackground=self.theme.FG_PRIMARY,
                        font=(self.theme.FONT_FAMILY, 13), width=40, relief=tk.FLAT, bd=5)
        entry.pack(pady=5, ipady=4)
        entry.focus_set()
        
        def apply_filter():
            self.capture_filter = filter_var.get().strip()
            if self.capturing and self.engine:
                self.engine.set_filter(self.capture_filter if self.capture_filter else None)
            self._set_status(f"Capture filter: {self.capture_filter or 'None'}")
            dialog.destroy()
        
        btn_frame = tk.Frame(dialog, bg=self.theme.BG_PRIMARY)
        btn_frame.pack(pady=15)
        tk.Button(btn_frame, text="Apply", command=apply_filter,
                 bg=self.theme.ACCENT_BLUE, fg='#000000', font=(self.theme.FONT_FAMILY_UI, 12, 'bold'),
                 relief=tk.FLAT, padx=20, pady=5).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Clear", command=lambda: (filter_var.set(""), apply_filter()),
                 bg=self.theme.BG_TERTIARY, fg=self.theme.FG_PRIMARY,
                 font=(self.theme.FONT_FAMILY_UI, 12), relief=tk.FLAT, padx=20, pady=5).pack(side=tk.LEFT, padx=5)
        
        entry.bind("<Return>", lambda e: apply_filter())

    def _dns_lookup(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("DNS Lookup")
        dialog.geometry("500x350")
        dialog.configure(bg=self.theme.BG_PRIMARY)
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="DNS Lookup", bg=self.theme.BG_PRIMARY,
                fg=self.theme.ACCENT_BLUE, font=(self.theme.FONT_FAMILY_UI, 16, 'bold')
                ).pack(pady=15)
        
        input_frame = tk.Frame(dialog, bg=self.theme.BG_PRIMARY)
        input_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Label(input_frame, text="Domain:", bg=self.theme.BG_PRIMARY,
                fg=self.theme.FG_SECONDARY).pack(side=tk.LEFT)
        
        domain_var = tk.StringVar()
        entry = tk.Entry(input_frame, textvariable=domain_var,
                        bg=self.theme.BG_INPUT, fg=self.theme.FG_PRIMARY,
                        insertbackground=self.theme.FG_PRIMARY,
                        font=(self.theme.FONT_FAMILY, 12), width=30, relief=tk.FLAT, bd=3)
        entry.pack(side=tk.LEFT, padx=10, ipady=3)
        entry.focus_set()
        
        result_text = scrolledtext.ScrolledText(dialog, bg='#0a0a1a', fg=self.theme.FG_PRIMARY,
                                               font=(self.theme.FONT_FAMILY, 11), height=10)
        result_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        def do_lookup():
            import socket
            domain = domain_var.get().strip()
            if not domain:
                return
            result_text.delete('1.0', tk.END)
            try:
                result_text.insert(tk.END, f"Looking up {domain}...\n\n")
                ips = socket.getaddrinfo(domain, None)
                result_text.insert(tk.END, f"Results for {domain}:\n")
                result_text.insert(tk.END, "-" * 40 + "\n")
                seen = set()
                for info in ips:
                    family, _, _, _, addr = info
                    ip = addr[0]
                    if ip not in seen:
                        seen.add(ip)
                        fam_name = "IPv4" if family == socket.AF_INET else "IPv6"
                        result_text.insert(tk.END, f"  {fam_name}: {ip}\n")
            except socket.gaierror as e:
                result_text.insert(tk.END, f"Error: {e}\n")
        
        tk.Button(dialog, text="Lookup", command=do_lookup,
                 bg=self.theme.ACCENT_BLUE, fg='#000000',
                 font=(self.theme.FONT_FAMILY_UI, 12, 'bold'),
                 relief=tk.FLAT, padx=20, pady=5).pack(pady=5)
        entry.bind("<Return>", lambda e: do_lookup())

    def _mac_lookup(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("MAC Vendor Lookup")
        dialog.geometry("450x250")
        dialog.configure(bg=self.theme.BG_PRIMARY)
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="MAC Vendor Lookup", bg=self.theme.BG_PRIMARY,
                fg=self.theme.ACCENT_BLUE, font=(self.theme.FONT_FAMILY_UI, 16, 'bold')
                ).pack(pady=15)
        
        input_frame = tk.Frame(dialog, bg=self.theme.BG_PRIMARY)
        input_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Label(input_frame, text="MAC:", bg=self.theme.BG_PRIMARY,
                fg=self.theme.FG_SECONDARY).pack(side=tk.LEFT)
        
        mac_var = tk.StringVar()
        entry = tk.Entry(input_frame, textvariable=mac_var,
                        bg=self.theme.BG_INPUT, fg=self.theme.FG_PRIMARY,
                        insertbackground=self.theme.FG_PRIMARY,
                        font=(self.theme.FONT_FAMILY, 12), width=25, relief=tk.FLAT, bd=3)
        entry.pack(side=tk.LEFT, padx=10, ipady=3)
        entry.focus_set()
        
        result_var = tk.StringVar()
        result_label = tk.Label(dialog, textvariable=result_var, bg=self.theme.BG_PRIMARY,
                               fg=self.theme.FG_PRIMARY, font=(self.theme.FONT_FAMILY, 14))
        result_label.pack(pady=15)
        
        def do_lookup():
            mac = mac_var.get().strip()
            if not mac:
                return
            vendor = MACVendorLookup.lookup(mac)
            result_var.set(f"Vendor: {vendor}")
        
        tk.Button(dialog, text="Lookup", command=do_lookup,
                 bg=self.theme.ACCENT_BLUE, fg='#000000',
                 font=(self.theme.FONT_FAMILY_UI, 12, 'bold'),
                 relief=tk.FLAT, padx=20, pady=5).pack(pady=5)
        entry.bind("<Return>", lambda e: do_lookup())

    def _whois_lookup(self):
        self._set_status("Whois lookup requires external tools")

    def _detection_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Detection Settings")
        dialog.geometry("500x550")
        dialog.configure(bg=self.theme.BG_PRIMARY)
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Threat Detection Settings", bg=self.theme.BG_PRIMARY,
                fg=self.theme.ACCENT_BLUE, font=(self.theme.FONT_FAMILY_UI, 16, 'bold')
                ).pack(pady=15)
        
        canvas = tk.Canvas(dialog, bg=self.theme.BG_PRIMARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(dialog, orient=tk.VERTICAL, command=canvas.yview)
        inner = tk.Frame(canvas, bg=self.theme.BG_PRIMARY)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        config = self.detector.config
        settings = [
            ("Port Scan Threshold", "PORT_SCAN_THRESHOLD", config.PORT_SCAN_THRESHOLD),
            ("Port Scan Window (s)", "PORT_SCAN_WINDOW", config.PORT_SCAN_WINDOW),
            ("SYN Flood Threshold", "SYN_FLOOD_THRESHOLD", config.SYN_FLOOD_THRESHOLD),
            ("SYN Flood Window (s)", "SYN_FLOOD_WINDOW", config.SYN_FLOOD_WINDOW),
            ("UDP Flood Threshold", "UDP_FLOOD_THRESHOLD", config.UDP_FLOOD_THRESHOLD),
            ("ICMP Flood Threshold", "ICMP_FLOOD_THRESHOLD", config.ICMP_FLOOD_THRESHOLD),
            ("HTTP Flood Threshold", "HTTP_FLOOD_THRESHOLD", config.HTTP_FLOOD_THRESHOLD),
            ("Brute Force Threshold", "BRUTE_FORCE_THRESHOLD", config.BRUTE_FORCE_THRESHOLD),
            ("Alert Cooldown (s)", "_alert_cooldown", self.detector._alert_cooldown),
        ]
        
        entries = {}
        for label, key, default in settings:
            row = tk.Frame(inner, bg=self.theme.BG_PRIMARY)
            row.pack(fill=tk.X, padx=20, pady=4)
            tk.Label(row, text=label, bg=self.theme.BG_PRIMARY, fg=self.theme.FG_SECONDARY,
                    font=(self.theme.FONT_FAMILY_UI, 11), width=25, anchor=tk.W).pack(side=tk.LEFT)
            var = tk.StringVar(value=str(default))
            entry = tk.Entry(row, textvariable=var, bg=self.theme.BG_INPUT, fg=self.theme.FG_PRIMARY,
                           font=(self.theme.FONT_FAMILY, 11), width=10, relief=tk.FLAT, bd=3)
            entry.pack(side=tk.RIGHT, ipady=2)
            entries[key] = var
        
        def save_settings():
            for key, var in entries.items():
                try:
                    value = int(var.get())
                    if key.startswith('_'):
                        setattr(self.detector, key, value)
                    else:
                        setattr(self.detector.config, key, value)
                except ValueError:
                    pass
            self._set_status("Detection settings updated")
            dialog.destroy()
        
        tk.Button(dialog, text="Save Settings", command=save_settings,
                 bg=self.theme.ACCENT_BLUE, fg='#000000',
                 font=(self.theme.FONT_FAMILY_UI, 12, 'bold'),
                 relief=tk.FLAT, padx=20, pady=8).pack(pady=15)

    def _show_statistics(self):
        """Show statistics view."""
        self.tab_notebook.select(0)
        self._update_statistics_tab()

    def _show_protocol_breakdown(self):
        self.tab_notebook.select(2)
        self._update_statistics_tab()

    def _show_traffic_graph(self):
        if HAS_MATPLOTLIB:
            self.tab_notebook.select(4)

    def _show_alerts_panel(self):
        self.tab_notebook.select(1)

    def _clear_packets(self):
        if self.packets:
            if not messagebox.askyesno("Confirm", "Clear all captured packets?"):
                return
        
        self.packets.clear()
        self._inc_total_bytes = 0
        self._inc_suspicious = 0
        self._inc_proto_counts = defaultdict(int)
        self._inc_src_ips = set()
        self._inc_dst_ips = set()
        self._inc_src_ip_counts = defaultdict(int)
        self._inc_dst_ip_counts = defaultdict(int)
        self._inc_conv_counts = defaultdict(lambda: {'count': 0, 'bytes': 0})
        for item in self.tree.get_children():
            self.tree.delete(item)
        for item in self.detail_tree.get_children():
            self.detail_tree.delete(item)
        self._update_quick_stats()
        self._set_status("Packet list cleared")

    def _load_interfaces(self):
        interfaces = PacketCaptureEngine.get_interfaces()
        iface_names = [i['name'] for i in interfaces]
        self.interface_combo['values'] = iface_names
        
        if iface_names:
            default = PacketCaptureEngine.get_default_interface()
            if default in iface_names:
                self.interface_var.set(default)
            else:
                self.interface_var.set(iface_names[0])

    # ═══════════════════════════════════════════════════════════════
    # UTILITIES
    # ═══════════════════════════════════════════════════════════════

    def _set_status(self, text: str):
        self.status_label.config(text=text)

    def _toggle_auto_scroll(self):
        self.auto_scroll = self._auto_scroll_var.get()

    def _format_bytes(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(size) < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    def _show_about(self):
        about_win = tk.Toplevel(self.root)
        about_win.title("About PacketVision Pro")
        about_win.geometry("500x400")
        about_win.configure(bg=self.theme.BG_PRIMARY)
        about_win.transient(self.root)
        about_win.grab_set()
        
        tk.Label(about_win, text="◈", font=("Arial", 48),
                bg=self.theme.BG_PRIMARY, fg=self.theme.ACCENT_BLUE).pack(pady=(30, 10))
        
        tk.Label(about_win, text=self.APP_NAME, bg=self.theme.BG_PRIMARY,
                fg=self.theme.FG_BRIGHT, font=(self.theme.FONT_FAMILY_UI, 24, 'bold')
                ).pack()
        
        tk.Label(about_win, text=f"Version {self.APP_VERSION}", bg=self.theme.BG_PRIMARY,
                fg=self.theme.FG_SECONDARY, font=(self.theme.FONT_FAMILY_UI, 12)).pack(pady=5)
        
        tk.Label(about_win, text="Advanced Network Packet Sniffer & Analyzer", bg=self.theme.BG_PRIMARY,
                fg=self.theme.FG_SECONDARY, font=(self.theme.FONT_FAMILY_UI, 11)).pack(pady=5)
        
        features = [
            "Live Packet Capture (Scapy)",
            "Protocol Detection & Decoding",
            "Suspicious Traffic Detection",
            "Modern Wireshark-Inspired GUI",
            "Export to CSV, PCAP, JSON",
            "Traffic Visualization",
            "SQLite Database Storage",
        ]
        
        tk.Label(about_win, text="Features:", bg=self.theme.BG_PRIMARY,
                fg=self.theme.ACCENT_BLUE, font=(self.theme.FONT_FAMILY_UI, 11, 'bold')
                ).pack(anchor=tk.W, padx=50, pady=(15, 5))
        
        for feat in features:
            tk.Label(about_win, text=f"  • {feat}", bg=self.theme.BG_PRIMARY,
                    fg=self.theme.FG_PRIMARY, font=(self.theme.FONT_FAMILY_UI, 10)
                    ).pack(anchor=tk.W, padx=50, pady=1)
        
        tk.Label(about_win, text="Cybersecurity Internship Project", bg=self.theme.BG_PRIMARY,
                fg=self.theme.FG_MUTED, font=(self.theme.FONT_FAMILY_UI, 10)
                ).pack(side=tk.BOTTOM, pady=10)

    def _on_close(self):
        """Handle window close."""
        if self.capturing:
            if messagebox.askyesno("Quit", "Capture is running. Stop and quit?"):
                self._stop_capture()
            else:
                return
        
        # Auto-generate PDF capture report
        if self.packets:
            try:
                self._set_status("Generating PDF report...")
                self.root.update()
                report_path = generate_report(
                    packets=self.packets,
                    alerts=self._alert_history,
                    interface=self.interface or "unknown",
                    start_time=self._capture_start_time,
                    end_time=time.time(),
                )
                if report_path:
                    logger.info(f"PDF report saved: {report_path}")
            except Exception as e:
                logger.error(f"Failed to generate PDF report: {e}")
        
        # Save DB info
        try:
            info = self.db.get_db_info()
            logger.info(f"Database: {info['packet_count']} packets, {info['size_mb']} MB")
        except Exception:
            pass
        
        self.root.destroy()

    def run(self):
        """Start the application."""
        self.root.mainloop()
