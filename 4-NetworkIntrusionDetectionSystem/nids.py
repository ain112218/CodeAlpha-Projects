"""
Network Intrusion Detection System (NIDS)
Author: Ain Azeem <azeem@warsawuni.edu.pl>

A simple network-based intrusion detection system that monitors
traffic, detects suspicious activity, and logs alerts.
"""

import sys
import os
import json
import time
import signal
import logging
import argparse
from datetime import datetime
from collections import defaultdict, deque
from threading import Thread, Lock

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

LOG_DIR = "logs"
ALERTS_FILE = os.path.join(LOG_DIR, "alerts.log")
TRAFFIC_FILE = os.path.join(LOG_DIR, "traffic.log")
STATS_FILE = os.path.join(LOG_DIR, "stats.json")

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(ALERTS_FILE, mode="a"),
    ],
)
logger = logging.getLogger("NIDS")


class AlertManager:
    """Manages alert generation, deduplication, and logging."""

    def __init__(self, cooldown=60):
        self.cooldown = cooldown
        self.recent_alerts = {}
        self.lock = Lock()
        self.alert_count = 0

    def _alert_key(self, alert_type, src_ip):
        return f"{alert_type}:{src_ip}"

    def send_alert(self, alert_type, src_ip, dst_ip, details, severity="HIGH"):
        key = self._alert_key(alert_type, src_ip)
        now = time.time()

        with self.lock:
            if key in self.recent_alerts:
                if now - self.recent_alerts[key] < self.cooldown:
                    return False
            self.recent_alerts[key] = now
            self.alert_count += 1

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = (
            f"[{severity}] {alert_type}\n"
            f"  Time:    {timestamp}\n"
            f"  Source:  {src_ip}\n"
            f"  Target:  {dst_ip}\n"
            f"  Details: {details}\n"
            f"  Alert#:  {self.alert_count}\n"
        )

        color_map = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m", "LOW": "\033[36m"}
        reset = "\033[0m"
        color = color_map.get(severity, "")
        print(f"\n{color}{'='*60}")
        print(f"ALERT: {alert_type}")
        print(f"{'='*60}{reset}")
        print(alert_msg)

        with open(ALERTS_FILE, "a") as f:
            f.write(f"--- Alert #{self.alert_count} ---\n{alert_msg}\n")

        return True

    def cleanup(self, max_age=300):
        now = time.time()
        with self.lock:
            self.recent_alerts = {
                k: v for k, v in self.recent_alerts.items() if now - v < max_age
            }


class TrafficStats:
    """Tracks network traffic statistics."""

    def __init__(self):
        self.lock = Lock()
        self.packet_count = 0
        self.byte_count = 0
        self.protocol_counts = defaultdict(int)
        self.ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.alert_counts = defaultdict(int)
        self.start_time = time.time()
        self.packets_per_second = deque(maxlen=100)

    def update(self, pkt):
        with self.lock:
            self.packet_count += 1
            if IP in pkt:
                self.byte_count += len(pkt)
                self.ip_counts[pkt[IP].src] += 1
                self.ip_counts[pkt[IP].dst] += 1

                if TCP in pkt:
                    self.protocol_counts["TCP"] += 1
                    self.port_counts[pkt[TCP].dport] += 1
                elif UDP in pkt:
                    self.protocol_counts["UDP"] += 1
                    self.port_counts[pkt[UDP].dport] += 1
                elif ICMP in pkt:
                    self.protocol_counts["ICMP"] += 1

    def record_alert(self, alert_type):
        with self.lock:
            self.alert_counts[alert_type] += 1

    def get_summary(self):
        elapsed = time.time() - self.start_time
        with self.lock:
            return {
                "uptime_seconds": round(elapsed, 1),
                "total_packets": self.packet_count,
                "total_bytes": self.byte_count,
                "packets_per_second": round(self.packet_count / max(elapsed, 1), 2),
                "protocols": dict(self.protocol_counts),
                "top_talkers": dict(
                    sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                ),
                "top_ports": dict(
                    sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                ),
                "alerts": dict(self.alert_counts),
            }

    def save(self):
        summary = self.get_summary()
        with open(STATS_FILE, "w") as f:
            json.dump(summary, f, indent=2)


class Detector:
    """Rule-based intrusion detection engine."""

    def __init__(self, rules_file="rules.json"):
        self.rules = self._load_rules(rules_file)
        self.syn_tracker = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)
        self.icmp_tracker = defaultdict(list)
        self.blocked_ips = set()
        self.lock = Lock()

    def _load_rules(self, path):
        default_rules = {
            "syn_flood": {
                "enabled": True,
                "threshold": 50,
                "window": 10,
                "severity": "CRITICAL",
            },
            "port_scan": {
                "enabled": True,
                "threshold": 15,
                "window": 30,
                "severity": "HIGH",
            },
            "icmp_flood": {
                "enabled": True,
                "threshold": 30,
                "window": 10,
                "severity": "HIGH",
            },
            "suspicious_ports": {
                "enabled": True,
                "ports": [4444, 5555, 6666, 31337, 12345, 54321],
                "severity": "HIGH",
            },
            "large_payload": {
                "enabled": True,
                "max_size": 8000,
                "severity": "MEDIUM",
            },
            "dns_tunnel": {
                "enabled": True,
                "threshold": 100,
                "window": 60,
                "severity": "HIGH",
            },
        }
        if os.path.exists(path):
            try:
                with open(path) as f:
                    user_rules = json.load(f)
                default_rules.update(user_rules)
                logger.info(f"Loaded rules from {path}")
            except Exception as e:
                logger.warning(f"Failed to load rules: {e}. Using defaults.")
        else:
            with open(path, "w") as f:
                json.dump(default_rules, f, indent=2)
            logger.info(f"Created default rules file: {path}")
        return default_rules

    def _is_blocked(self, ip):
        with self.lock:
            return ip in self.blocked_ips

    def block_ip(self, ip):
        with self.lock:
            self.blocked_ips.add(ip)
        logger.warning(f"BLOCKED IP: {ip}")

    def check_syn_flood(self, pkt, alert_mgr, stats):
        rule = self.rules.get("syn_flood", {})
        if not rule.get("enabled") or not (TCP in pkt and pkt[TCP].flags == "S"):
            return
        src = pkt[IP].src
        now = time.time()
        window = rule.get("window", 10)
        threshold = rule.get("threshold", 50)

        with self.lock:
            self.syn_tracker[src].append(now)
            self.syn_tracker[src] = [t for t in self.syn_tracker[src] if now - t < window]
            if len(self.syn_tracker[src]) >= threshold:
                alert_mgr.send_alert(
                    "SYN_FLOOD",
                    src,
                    pkt[IP].dst,
                    f"{len(self.syn_tracker[src])} SYN packets in {window}s (threshold: {threshold})",
                    rule.get("severity", "CRITICAL"),
                )
                stats.record_alert("SYN_FLOOD")
                self.block_ip(src)
                self.syn_tracker[src] = []

    def check_port_scan(self, pkt, alert_mgr, stats):
        rule = self.rules.get("port_scan", {})
        if not rule.get("enabled") or not (TCP in pkt and pkt[TCP].flags == "S"):
            return
        src = pkt[IP].src
        dst_port = pkt[TCP].dport
        now = time.time()
        window = rule.get("window", 30)
        threshold = rule.get("threshold", 15)

        with self.lock:
            key = f"{src}:{now // window}"
            self.port_scan_tracker[key].add(dst_port)
            if len(self.port_scan_tracker[key]) >= threshold:
                alert_mgr.send_alert(
                    "PORT_SCAN",
                    src,
                    pkt[IP].dst,
                    f"Scanned {len(self.port_scan_tracker[key])} unique ports in {window}s",
                    rule.get("severity", "HIGH"),
                )
                stats.record_alert("PORT_SCAN")
                self.block_ip(src)
                self.port_scan_tracker[key] = set()

    def check_icmp_flood(self, pkt, alert_mgr, stats):
        rule = self.rules.get("icmp_flood", {})
        if not rule.get("enabled") or not ICMP in pkt:
            return
        src = pkt[IP].src
        now = time.time()
        window = rule.get("window", 10)
        threshold = rule.get("threshold", 30)

        with self.lock:
            self.icmp_tracker[src].append(now)
            self.icmp_tracker[src] = [t for t in self.icmp_tracker[src] if now - t < window]
            if len(self.icmp_tracker[src]) >= threshold:
                alert_mgr.send_alert(
                    "ICMP_FLOOD",
                    src,
                    pkt[IP].dst,
                    f"{len(self.icmp_tracker[src])} ICMP packets in {window}s",
                    rule.get("severity", "HIGH"),
                )
                stats.record_alert("ICMP_FLOOD")
                self.icmp_tracker[src] = []

    def check_suspicious_ports(self, pkt, alert_mgr, stats):
        rule = self.rules.get("suspicious_ports", {})
        if not rule.get("enabled"):
            return
        if TCP in pkt:
            dport = pkt[TCP].dport
        elif UDP in pkt:
            dport = pkt[UDP].dport
        else:
            return

        if dport in rule.get("ports", []):
            alert_mgr.send_alert(
                "SUSPICIOUS_PORT",
                pkt[IP].src,
                pkt[IP].dst,
                f"Connection to known suspicious port {dport}",
                rule.get("severity", "HIGH"),
            )
            stats.record_alert("SUSPICIOUS_PORT")

    def check_large_payload(self, pkt, alert_mgr, stats):
        rule = self.rules.get("large_payload", {})
        if not rule.get("enabled") or not Raw in pkt:
            return
        payload_size = len(pkt[Raw].load)
        max_size = rule.get("max_size", 8000)
        if payload_size > max_size:
            alert_mgr.send_alert(
                "LARGE_PAYLOAD",
                pkt[IP].src,
                pkt[IP].dst,
                f"Payload size: {payload_size} bytes (max: {max_size})",
                rule.get("severity", "MEDIUM"),
            )
            stats.record_alert("LARGE_PAYLOAD")

    def analyze(self, pkt, alert_mgr, stats):
        if not IP in pkt:
            return
        if self._is_blocked(pkt[IP].src):
            return
        stats.update(pkt)
        self.check_syn_flood(pkt, alert_mgr, stats)
        self.check_port_scan(pkt, alert_mgr, stats)
        self.check_icmp_flood(pkt, alert_mgr, stats)
        self.check_suspicious_ports(pkt, alert_mgr, stats)
        self.check_large_payload(pkt, alert_mgr, stats)


class NIDS:
    """Main Network Intrusion Detection System."""

    def __init__(self, interface=None, rules_file="rules.json", count=0):
        self.interface = interface
        self.count = count
        self.detector = Detector(rules_file)
        self.alert_mgr = AlertManager()
        self.stats = TrafficStats()
        self.running = False

    def _packet_handler(self, pkt):
        try:
            self.detector.analyze(pkt, self.alert_mgr, self.stats)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def start(self):
        if not SCAPY_AVAILABLE:
            logger.error("scapy is not installed. Run setup first.")
            sys.exit(1)

        self.running = True
        logger.info("=" * 60)
        logger.info("  Network Intrusion Detection System Started")
        logger.info(f"  Interface: {self.interface or 'default'}")
        logger.info(f"  Rules loaded: {len(self.detector.rules)}")
        logger.info(f"  Alerts log: {ALERTS_FILE}")
        logger.info(f"  Stats log: {STATS_FILE}")
        logger.info("=" * 60)
        logger.info("Monitoring network traffic... Press Ctrl+C to stop.\n")

        def periodic_save():
            while self.running:
                time.sleep(30)
                self.stats.save()
                self.alert_mgr.cleanup()

        saver = Thread(target=periodic_save, daemon=True)
        saver.start()

        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                count=self.count if self.count > 0 else 0,
                store=False,
            )
        except PermissionError:
            logger.error("Permission denied. Run as administrator/root.")
            sys.exit(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self.running = False
        self.stats.save()
        summary = self.stats.get_summary()
        logger.info("\n" + "=" * 60)
        logger.info("  NIDS Shutdown Summary")
        logger.info("=" * 60)
        logger.info(f"  Total packets analyzed: {summary['total_packets']}")
        logger.info(f"  Total bytes: {summary['total_bytes']}")
        logger.info(f"  Alerts triggered: {sum(summary['alerts'].values())}")
        logger.info(f"  Uptime: {summary['uptime_seconds']}s")
        logger.info("=" * 60)
        logger.info("Traffic stats saved to " + STATS_FILE)


def list_interfaces():
    if SCAPY_AVAILABLE:
        from scapy.all import get_if_list
        print("\nAvailable network interfaces:")
        for i, iface in enumerate(get_if_list()):
            print(f"  [{i}] {iface}")
        print()
    else:
        print("Install scapy to list interfaces: pip install scapy")


def main():
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System (NIDS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nids.py                          Start with default interface
  python nids.py -i "Ethernet"            Use specific interface
  python nids.py -c 1000                  Capture 1000 packets then stop
  python nids.py --list-interfaces        Show available interfaces
  python nids.py --rules custom_rules.json Use custom rules file
        """,
    )
    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-r", "--rules", default="rules.json", help="Path to rules JSON file")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard after capture")

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    nids = NIDS(interface=args.interface, rules_file=args.rules, count=args.count)

    def signal_handler(sig, frame):
        logger.info("\nStopping NIDS...")
        nids.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    nids.start()

    if args.dashboard:
        try:
            from dashboard import launch_dashboard
            launch_dashboard()
        except ImportError:
            logger.warning("Dashboard not available. Install matplotlib: pip install matplotlib")


if __name__ == "__main__":
    main()
