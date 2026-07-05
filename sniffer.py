#!/usr/bin/env python3
"""
sniffer.py — Basic Network Sniffer (CodeAlpha Cyber Security Internship — Task 1)

Captures live network packets and displays:
    - Source IP
    - Destination IP
    - Protocol
    - Packet Length

Requirements:
    pip install scapy

Usage:
    sudo python3 sniffer.py                 # sniff on default interface, all traffic
    sudo python3 sniffer.py -i eth0         # sniff on a specific interface
    sudo python3 sniffer.py -c 50           # stop after 50 packets
    sudo python3 sniffer.py -f "tcp port 80"  # apply a BPF filter

Note: Raw packet capture requires elevated privileges (run with sudo/admin).
"""

import argparse
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


# Maps protocol numbers to readable names for the common cases.
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def process_packet(packet):
    """Callback invoked for every captured packet."""
    if not packet.haslayer(IP):
        return  # Skip non-IP traffic (e.g. ARP) to keep output focused.

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto_num = ip_layer.proto
    proto_name = PROTOCOL_NAMES.get(proto_num, f"OTHER({proto_num})")
    length = len(packet)
    timestamp = datetime.now().strftime("%H:%M:%S")

    line = f"[{timestamp}] {src_ip:>15} -> {dst_ip:<15} | Proto: {proto_name:<10} | Len: {length} bytes"

    # Add port info when available for extra context.
    if packet.haslayer(TCP):
        line += f" | Sport: {packet[TCP].sport} Dport: {packet[TCP].dport}"
    elif packet.haslayer(UDP):
        line += f" | Sport: {packet[UDP].sport} Dport: {packet[UDP].dport}"

    print(line)

    # Optionally show a short preview of the raw payload, if present.
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        preview = payload[:32]
        print(f"    Payload preview: {preview}")


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer using Scapy")
    parser.add_argument("-i", "--interface", default=None,
                         help="Network interface to sniff on (default: Scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = infinite, until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="ip",
                         help='BPF filter string (default: "ip", e.g. "tcp port 80")')
    args = parser.parse_args()

    print("Starting network sniffer... Press Ctrl+C to stop.\n")
    print(f"Interface : {args.interface or 'default'}")
    print(f"Filter    : {args.filter}")
    print(f"Count     : {'unlimited' if args.count == 0 else args.count}\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=process_packet,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print("Permission denied. Try running this script with sudo/administrator privileges.")
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")


if __name__ == "__main__":
    main()