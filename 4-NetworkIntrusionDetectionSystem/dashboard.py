"""
Simple dashboard for visualizing NIDS alerts and traffic stats.
Author: Ain Azeem <azeem@warsawuni.edu.pl>
"""

import json
import os
import sys
from datetime import datetime

STATS_FILE = os.path.join("logs", "stats.json")
ALERTS_FILE = os.path.join("logs", "alerts.log")


def load_stats():
    if os.path.exists(STATS_FILE):
        with open(STATS_FILE) as f:
            return json.load(f)
    return None


def load_alerts():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE) as f:
            content = f.read()
        blocks = content.split("--- Alert #")
        for block in blocks[1:]:
            alerts.append(block.strip())
    return alerts


def print_stats_bar(label, value, max_val, width=40):
    if max_val == 0:
        filled = 0
    else:
        filled = int((value / max_val) * width)
    bar = "█" * filled + "░" * (width - filled)
    print(f"  {label:<20} |{bar}| {value}")


def show_dashboard():
    stats = load_stats()
    alerts = load_alerts()

    while True:
        os.system("cls" if os.name == "nt" else "clear")
        print("=" * 70)
        print("       NETWORK INTRUSION DETECTION SYSTEM - DASHBOARD")
        print(f"       Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        if stats:
            print(f"\n  Uptime: {stats.get('uptime_seconds', 0)}s")
            print(f"  Packets analyzed: {stats.get('total_packets', 0)}")
            print(f"  Data processed: {stats.get('total_bytes', 0)} bytes")
            print(f"  Rate: {stats.get('packets_per_second', 0)} pkts/sec")

            protocols = stats.get("protocols", {})
            if protocols:
                print("\n  --- Protocol Distribution ---")
                max_proto = max(protocols.values()) if protocols else 1
                for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                    print_stats_bar(proto, count, max_proto, 30)

            top_talkers = stats.get("top_talkers", {})
            if top_talkers:
                print("\n  --- Top Talkers (IP addresses) ---")
                max_talker = max(top_talkers.values()) if top_talkers else 1
                for ip, count in list(top_talkers.items())[:8]:
                    print_stats_bar(ip, count, max_talker, 30)

            alert_summary = stats.get("alerts", {})
            if alert_summary:
                print("\n  --- Alert Summary ---")
                total_alerts = sum(alert_summary.values())
                print(f"  Total alerts: {total_alerts}")
                for atype, count in sorted(alert_summary.items(), key=lambda x: x[1], reverse=True):
                    print(f"    {atype}: {count}")
        else:
            print("\n  No stats available yet. Start the NIDS first.")

        if alerts:
            print(f"\n  --- Recent Alerts (last {min(5, len(alerts))}) ---")
            for alert in alerts[-5:]:
                lines = alert.split("\n")
                for line in lines[:6]:
                    print(f"  {line}")
                print("  " + "-" * 50)

        print("\n  [R] Refresh  [Q] Quit")
        choice = input("\n  > ").strip().lower()
        if choice == "q":
            break
        stats = load_stats()
        alerts = load_alerts()


def launch_dashboard():
    try:
        show_dashboard()
    except KeyboardInterrupt:
        print("\nDashboard closed.")


if __name__ == "__main__":
    launch_dashboard()
