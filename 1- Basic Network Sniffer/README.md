# Basic Network Sniffer

A Python-based packet sniffer that captures and analyzes network traffic in real time. Built with `scapy` for educational purposes — learn how data flows through a network and understand protocol structures.

## Features

- Captures live network packets on any interface
- Displays source/destination MAC and IP addresses
- Identifies protocol: TCP, UDP, ICMP, or other
- Shows TCP/UDP port numbers and TCP flags
- Prints payload content in hex + ASCII format
- BPF filter support (e.g. capture only TCP traffic)
- Configurable packet count limit
- Clean, color-free terminal output
- Runs in an isolated Python virtual environment

## Prerequisites

- **Windows** 10 or 11
- **Python 3.8+** — [Download here](https://www.python.org/downloads/)
- **Npcap** — [Download here](https://npcap.com/) (install with *"WinPcap API-compatible Mode"* checked)

## Installation

### 1. Install Npcap

Download and install Npcap from [npcap.com](https://npcap.com/). During setup, make sure to check:

> ✅ Install in WinPcap API-compatible Mode

### 2. Run setup (one time only)

Right-click **`setup.bat`** and select **Run as administrator**.

This will:
- Verify Python and Npcap are installed
- Create an isolated virtual environment (`venv/`)
- Install `scapy` and dependencies

You only need to do this once.

## Usage

Right-click **`run.bat`** and select **Run as administrator**.

The sniffer will start capturing packets immediately. Press **Ctrl+C** to stop.

### Command-line options

| Option | Description |
|--------|-------------|
| `-c N` | Capture only N packets, then exit |
| `-i IFACE` | Listen on a specific network interface |
| `-f EXPR` | BPF filter expression (e.g. `tcp`, `udp`, `icmp`, `port 80`) |
| `-h` | Show help |

### Examples

Capture 5 packets:
```
python sniffer.py -c 5
```

Capture only TCP traffic:
```
python sniffer.py -f tcp
```

Capture 10 HTTP packets on a specific interface:
```
python sniffer.py -i "Wi-Fi" -c 10 -f "port 80"
```

### Sample output

```
Basic Network Sniffer
================================================================================
Interface: default
Filter:    none
Packets:   unlimited
Press Ctrl+C to stop.
================================================================================
[14:23:05] TCP  192.168.1.5 -> 142.250.80.14  (66 bytes)
          Src Port: 54321  Dst Port: 443
          Flags: A
          Payload: [No payload]
--------------------------------------------------------------------------------
[14:23:05] UDP  192.168.1.5 -> 8.8.8.8  (74 bytes)
          Src Port: 54322  Dst Port: 53
          Payload: [Empty]
--------------------------------------------------------------------------------
```

## Project structure

| File | Purpose |
|------|---------|
| `sniffer.py` | Main packet sniffer |
| `setup.bat` | One-time environment setup |
| `run.bat` | Launch the sniffer |
| `requirements.txt` | Python dependencies |
| `README.md` | This file |

## Notes

- **Administrator privileges** are required for packet capture on Windows.
- Only capture traffic on networks you own or have explicit permission to monitor.
- The virtual environment (`venv/`) keeps dependencies isolated from your system Python.

## Author

**Ain Azeem** — [azeem@warsawuni.edu.pl](mailto:azeem@warsawuni.edu.pl)

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
# codealpha
