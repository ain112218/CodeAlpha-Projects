# Network Intrusion Detection System (NIDS)

A simple, rule-based network intrusion detection system that monitors network traffic, detects suspicious activity, and logs alerts in real-time.

## Author

**Ain Azeem**  
Email: azeem@warsawuni.edu.pl

## Features

- **Real-time packet sniffing** using Scapy
- **Rule-based detection** for common attacks:
  - SYN Flood attacks
  - Port scanning
  - ICMP (Ping) flood
  - Suspicious port connections (C2/malware ports)
  - Large payload detection (data exfiltration)
  - DNS tunneling detection
- **Automatic IP blocking** for detected attackers
- **Alert logging** with severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- **Traffic statistics** and top-talkers tracking
- **Console dashboard** for live visualization
- **Configurable rules** via `rules.json`

## Quick Start (Non-Technical Users)

### Windows

1. **Setup** - Double-click `setup.bat` (one-time only)
2. **Run** - Double-click `run.bat`
3. **Dashboard** - After stopping, run `python dashboard.py` or use `run.bat --dashboard`

### Linux / macOS

```bash
# Setup (one-time only)
chmod +x setup.sh
./setup.sh

# Run
chmod +x run.sh
./run.sh
```

### With Admin Privileges

On Windows, right-click `run.bat` and select **Run as Administrator**.  
On Linux/macOS:

```bash
sudo ./run.sh
```

> Administrator/root privileges are required for packet sniffing.

## Command-Line Options

```
python nids.py [options]

  -i, --interface     Network interface to monitor (e.g., "Ethernet", "wlan0")
  -c, --count         Number of packets to capture (0 = unlimited)
  -r, --rules         Path to custom rules JSON file
  --list-interfaces   Show available network interfaces
  --dashboard         Launch dashboard after capture
```

### Examples

```bash
python nids.py                         # Default interface, unlimited capture
python nids.py -i "Ethernet"           # Specific interface
python nids.py -c 5000                 # Capture 5000 packets then stop
python nids.py --list-interfaces       # List available interfaces
python nids.py --dashboard             # NIDS + live dashboard
```

## Project Structure

```
.
├── nids.py              # Main NIDS engine
├── dashboard.py         # Console-based visualization
├── rules.json           # Detection rules (editable)
├── requirements.txt     # Python dependencies
├── setup.bat            # Windows setup script
├── setup.sh             # Linux/macOS setup script
├── run.bat              # Windows run script
├── run.sh               # Linux/macOS run script
├── .gitignore           # Git ignore rules
└── logs/                # Generated at runtime
    ├── alerts.log       # Alert history
    ├── traffic.log      # Traffic log
    └── stats.json       # Traffic statistics
```

## Customizing Rules

Edit `rules.json` to adjust detection thresholds:

| Rule | Parameter | Description |
|------|-----------|-------------|
| `syn_flood` | `threshold` | SYN packets before alert (default: 50) |
| `syn_flood` | `window` | Time window in seconds (default: 10) |
| `port_scan` | `threshold` | Unique ports before alert (default: 15) |
| `icmp_flood` | `threshold` | ICMP packets before alert (default: 30) |
| `suspicious_ports` | `ports` | List of flagged ports |
| `large_payload` | `max_size` | Max payload bytes before alert (default: 8000) |

Set `"enabled": false` to disable any rule.

## Requirements

- Python 3.8+
- Administrator/root privileges for packet capture

## License

Academic use - CodeAlpha Cyber Security Project
