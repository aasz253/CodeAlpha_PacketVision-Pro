#!/bin/bash
# PacketVision Pro - One-Click Installer for Linux/macOS
# Usage: curl -sL <url>/install.sh | bash
#    OR: chmod +x install.sh && ./install.sh

set -e
echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     PacketVision Pro - Installer         ║"
echo "  ║     Advanced Network Packet Sniffer      ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 not found. Install it first:"
    echo "  Ubuntu/Debian:  sudo apt install python3 python3-pip python3-venv python3-tk"
    echo "  macOS:          brew install python3"
    echo "  Fedora:         sudo dnf install python3 python3-pip python3-tkinter"
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[OK] Python $PY_VERSION found"

# Check pip
if ! python3 -m pip --version &> /dev/null; then
    echo "[...] Installing pip..."
    python3 -m ensurepip --upgrade 2>/dev/null || sudo apt install python3-pip -y 2>/dev/null || {
        echo "[ERROR] Cannot install pip. Run: sudo apt install python3-pip"
        exit 1
    }
fi

# Detect platform-specific packages
echo "[...] Checking system dependencies..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Debian/Ubuntu/Kali
    if command -v apt &> /dev/null; then
        sudo apt install -y python3-tk libpcap-dev 2>/dev/null || true
    # Fedora/RHEL
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y python3-tkinter libpcap-devel 2>/dev/null || true
    # Arch
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm tk libpcap 2>/dev/null || true
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    if command -v brew &> /dev/null; then
        brew install libpcap 2>/dev/null || true
    fi
fi

# Create virtual environment
echo "[...] Setting up virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo "[...] Installing Python packages..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  Installation complete!                  ║"
echo "  ╠══════════════════════════════════════════╣"
echo "  ║  To run:                                 ║"
echo "  ║    source venv/bin/activate              ║"
echo "  ║    sudo python3 main.py                  ║"
echo "  ║                                          ║"
echo "  ║  Or use:  ./run.sh                       ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
