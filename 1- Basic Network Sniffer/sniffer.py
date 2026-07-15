# Basic Network Sniffer
# Author: Ain Azeem
# Email: azeem@warsawuni.edu.pl

import sys
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw


def get_protocol_name(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def format_payload(payload, max_bytes=48):
    if not payload:
        return "[No payload]"
    raw = bytes(payload[:max_bytes])
    hex_part = " ".join(f"{b:02x}" for b in raw)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
    return f"{hex_part}  {ascii_part}"


def packet_handler(pkt):
    timestamp = time.strftime("%H:%M:%S")

    if pkt.haslayer(IP):
        ip = pkt[IP]
        proto = get_protocol_name(pkt)
        src_ip = ip.src
        dst_ip = ip.dst
        size = len(pkt)

        print(f"[{timestamp}] {proto}  {src_ip} -> {dst_ip}  ({size} bytes)")

        if pkt.haslayer(Ether):
            print(f"          MAC: {pkt[Ether].src} -> {pkt[Ether].dst}")

        if pkt.haslayer(TCP):
            print(f"          Src Port: {pkt[TCP].sport}  Dst Port: {pkt[TCP].dport}")
            flags = pkt[TCP].flags
            print(f"          Flags: {flags}")
        elif pkt.haslayer(UDP):
            print(f"          Src Port: {pkt[UDP].sport}  Dst Port: {pkt[UDP].dport}")

        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            print(f"          Payload: {format_payload(payload)}")
        else:
            print(f"          Payload: [Empty]")

        print("-" * 80)

    else:
        print(f"[{timestamp}] Non-IP packet ({len(pkt)} bytes)")
        print("-" * 80)


def main():
    packet_count = 10
    interface = None
    filter_expr = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("-c", "--count"):
            i += 1
            if i < len(args):
                packet_count = int(args[i])
        elif args[i] in ("-i", "--interface"):
            i += 1
            if i < len(args):
                interface = args[i]
        elif args[i] in ("-f", "--filter"):
            i += 1
            if i < len(args):
                filter_expr = args[i]
        elif args[i] in ("-h", "--help"):
            print("Usage: python sniffer.py [options]")
            print("  -c, --count N        Capture N packets (default: 10)")
            print("  -i, --interface IF   Listen on specific interface")
            print("  -f, --filter EXPR    BPF filter expression (e.g. 'tcp')")
            print("  -h, --help           Show this help")
            return
        i += 1

    print("Basic Network Sniffer")
    print("Author: Ain Azeem")
    print("=" * 80)
    print(f"Interface: {interface or 'default'}")
    print(f"Filter:    {filter_expr or 'none'}")
    print(f"Packets:   {'unlimited' if packet_count == 0 else packet_count}")
    print("Press Ctrl+C to stop.")
    print("=" * 80)

    try:
        sniff(
            count=packet_count if packet_count > 0 else 0,
            iface=interface,
            filter=filter_expr,
            prn=packet_handler,
            store=False,
        )
    except PermissionError:
        print("\n[ERROR] Permission denied. Run as Administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[+] Sniffer stopped by user.")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
