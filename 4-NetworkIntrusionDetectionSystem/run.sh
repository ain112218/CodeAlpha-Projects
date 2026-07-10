#!/bin/bash
echo "============================================"
echo "  Starting Network Intrusion Detection System"
echo "  Press Ctrl+C to stop"
echo "============================================"
echo ""

if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run ./setup.sh first."
    exit 1
fi

source venv/bin/activate
python3 nids.py "$@"

echo ""
echo "NIDS stopped. Check logs folder for alerts and stats."
