"""
PacketVision Pro - Theme & Style Constants
=============================================

Defines the color palettes, font settings, and sizing constants for both
dark mode and light mode themes. The dark theme is inspired by Wireshark's
interface and cybersecurity dashboard aesthetics.

Classes:
    DarkTheme        - Color palette for dark mode (default)
    LightTheme       - Color palette for light mode
    ProtocolColors   - Maps protocol names to distinct colors for the packet list

Each theme defines:
    - Background colors (primary, secondary, card, input, header)
    - Text colors (primary, secondary, muted, bright)
    - Accent colors (blue, green, red, orange, purple, etc.)
    - Protocol-specific colors for the packet list
    - Status and severity indicator colors
    - Font families and sizes
    - Spacing and sizing constants
"""


class DarkTheme:
    """Dark mode theme colors."""
    
    # Background colors
    BG_PRIMARY = "#1a1a2e"
    BG_SECONDARY = "#16213e"
    BG_TERTIARY = "#0f3460"
    BG_CARD = "#1e2a3a"
    BG_INPUT = "#2a3a4a"
    BG_HOVER = "#2d4a5a"
    BG_SELECTED = "#3a5a7a"
    BG_HEADER = "#0a1628"
    
    # Text colors
    FG_PRIMARY = "#e8e8e8"
    FG_SECONDARY = "#a0a0a0"
    FG_MUTED = "#6c757d"
    FG_BRIGHT = "#ffffff"
    FG_LABEL = "#8892a0"
    
    # Accent colors
    ACCENT_BLUE = "#00d4ff"
    ACCENT_GREEN = "#00ff88"
    ACCENT_RED = "#ff4757"
    ACCENT_ORANGE = "#ffa502"
    ACCENT_YELLOW = "#ffed4a"
    ACCENT_PURPLE = "#a855f7"
    ACCENT_CYAN = "#22d3ee"
    ACCENT_PINK = "#f472b6"
    
    # Protocol colors
    TCP_COLOR = "#00d4ff"
    UDP_COLOR = "#00ff88"
    ICMP_COLOR = "#ffa502"
    ARP_COLOR = "#a855f7"
    DNS_COLOR = "#f472b6"
    HTTP_COLOR = "#ff4757"
    HTTPS_COLOR = "#22d3ee"
    OTHER_COLOR = "#6c757d"
    
    # Status colors
    STATUS_SUCCESS = "#00ff88"
    STATUS_WARNING = "#ffa502"
    STATUS_ERROR = "#ff4757"
    STATUS_INFO = "#00d4ff"
    
    # Severity colors
    SEV_LOW = "#22d3ee"
    SEV_MEDIUM = "#ffa502"
    SEV_HIGH = "#ff4757"
    SEV_CRITICAL = "#dc143c"
    
    # Border
    BORDER_COLOR = "#2a3a4a"
    BORDER_ACTIVE = "#00d4ff"
    
    # Font
    FONT_FAMILY = "Consolas"
    FONT_FAMILY_UI = "Segoe UI"
    FONT_SIZE_SM = 11
    FONT_SIZE_MD = 12
    FONT_SIZE_LG = 14
    FONT_SIZE_XL = 16
    FONT_SIZE_TITLE = 20
    FONT_SIZE_HEADER = 24
    
    # Sizing
    SIDEBAR_WIDTH = 220
    STATS_BAR_HEIGHT = 50
    TREE_ROW_HEIGHT = 28
    PADDING_SM = 4
    PADDING_MD = 8
    PADDING_LG = 12
    PADDING_XL = 16
    
    # Border radius
    RADIUS_SM = 4
    RADIUS_MD = 6
    RADIUS_LG = 8
    RADIUS_XL = 12


class LightTheme:
    """Light mode theme colors."""
    
    BG_PRIMARY = "#ffffff"
    BG_SECONDARY = "#f5f5f5"
    BG_TERTIARY = "#e8e8e8"
    BG_CARD = "#ffffff"
    BG_INPUT = "#f0f0f0"
    BG_HOVER = "#e0e0e0"
    BG_SELECTED = "#d0e0f0"
    BG_HEADER = "#f8f8f8"
    
    FG_PRIMARY = "#1a1a1a"
    FG_SECONDARY = "#555555"
    FG_MUTED = "#888888"
    FG_BRIGHT = "#000000"
    FG_LABEL = "#333333"
    
    ACCENT_BLUE = "#0066cc"
    ACCENT_GREEN = "#28a745"
    ACCENT_RED = "#dc3545"
    ACCENT_ORANGE = "#fd7e14"
    ACCENT_YELLOW = "#ffc107"
    ACCENT_PURPLE = "#6f42c1"
    ACCENT_CYAN = "#17a2b8"
    ACCENT_PINK = "#e83e8c"
    
    TCP_COLOR = "#0066cc"
    UDP_COLOR = "#28a745"
    ICMP_COLOR = "#fd7e14"
    ARP_COLOR = "#6f42c1"
    DNS_COLOR = "#e83e8c"
    HTTP_COLOR = "#dc3545"
    HTTPS_COLOR = "#17a2b8"
    OTHER_COLOR = "#888888"
    
    STATUS_SUCCESS = "#28a745"
    STATUS_WARNING = "#fd7e14"
    STATUS_ERROR = "#dc3545"
    STATUS_INFO = "#17a2b8"
    
    SEV_LOW = "#17a2b8"
    SEV_MEDIUM = "#fd7e14"
    SEV_HIGH = "#dc3545"
    SEV_CRITICAL = "#8b0000"
    
    BORDER_COLOR = "#d0d0d0"
    BORDER_ACTIVE = "#0066cc"
    
    FONT_FAMILY = "Consolas"
    FONT_FAMILY_UI = "Segoe UI"
    FONT_SIZE_SM = 11
    FONT_SIZE_MD = 12
    FONT_SIZE_LG = 14
    FONT_SIZE_XL = 16
    FONT_SIZE_TITLE = 20
    FONT_SIZE_HEADER = 24
    
    SIDEBAR_WIDTH = 220
    STATS_BAR_HEIGHT = 50
    TREE_ROW_HEIGHT = 28
    PADDING_SM = 4
    PADDING_MD = 8
    PADDING_LG = 12
    PADDING_XL = 16
    
    RADIUS_SM = 4
    RADIUS_MD = 6
    RADIUS_LG = 8
    RADIUS_XL = 12


class ProtocolColors:
    """Map protocol names to colors."""
    
    COLORS = {
        'TCP': DarkTheme.TCP_COLOR,
        'UDP': DarkTheme.UDP_COLOR,
        'ICMP': DarkTheme.ICMP_COLOR,
        'ARP': DarkTheme.ARP_COLOR,
        'DNS': DarkTheme.DNS_COLOR,
        'HTTP': DarkTheme.HTTP_COLOR,
        'HTTPS': DarkTheme.HTTPS_COLOR,
    }
    
    @classmethod
    def get(cls, protocol: str) -> str:
        return cls.COLORS.get(protocol, DarkTheme.OTHER_COLOR)
    
    @classmethod
    def get_for_tree(cls, protocol: str) -> str:
        """Get treeview tag name for protocol."""
        return protocol.lower() if protocol in cls.COLORS else 'other'


def get_theme(dark_mode: bool = True):
    """Get theme based on mode."""
    return DarkTheme if dark_mode else LightTheme


# Tkinter compatible color dict for ttk.Treeview
def get_treeview_tags(theme):
    """Get treeview tag configurations."""
    return {
        'tcp': {'foreground': theme.TCP_COLOR},
        'udp': {'foreground': theme.UDP_COLOR},
        'icmp': {'foreground': theme.ICMP_COLOR},
        'arp': {'foreground': theme.ARP_COLOR},
        'dns': {'foreground': theme.DNS_COLOR},
        'http': {'foreground': theme.HTTP_COLOR},
        'https': {'foreground': theme.HTTPS_COLOR},
        'other': {'foreground': theme.OTHER_COLOR},
        'suspicious': {'foreground': theme.ACCENT_RED, 'background': '#2a1010'},
    }
