#!/bin/bash
echo "============================================"
echo "  Network Intrusion Detection System"
echo "  Setup Script"
echo "============================================"
echo ""

echo "[1/3] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed."
    echo "Install with: sudo apt install python3 python3-pip python3-venv"
    exit 1
fi
python3 --version
echo ""

echo "[2/3] Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
else
    echo "Virtual environment already exists."
fi
echo ""

echo "[3/3] Installing dependencies..."
source venv/bin/activate
pip install -r requirements.txt
echo ""

echo "============================================"
echo "  Setup complete!"
echo ""
echo "  To run the NIDS: ./run.sh"
echo "============================================"
