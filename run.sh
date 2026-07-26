#!/bin/bash
# PacketVision Pro - Quick Launch Script
# Usage: ./run.sh

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# Activate venv if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run with sudo for packet capture
echo "Starting PacketVision Pro..."
echo "(Requires sudo for live packet capture)"
sudo python3 main.py "$@"
