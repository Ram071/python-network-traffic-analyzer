"""Network Traffic Analyzer using Scapy.

Captures IP packet metadata on an authorized interface and writes a CSV log.
Run with the required packet-capture permissions for your operating system.
"""

import csv
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR
except ImportError:
    raise SystemExit(
        "Scapy is not installed. Install dependencies with: "
        "python -m pip install -r requirements.txt"
    )

CSV_FILE = Path(__file__).resolve().parent / "packet_log.csv"
protocol_counts = Counter()
total_packets = 0
capture_started = None

CSV_HEADERS = [
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Packet Size (bytes)",
    "DNS Query",
]


def identify_protocol(packet) -> str:
    """Return the most specific common protocol recognized in the packet."""
    if DNS in packet:
        return "DNS"
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    return "OTHER"


def get_ip_layer(packet):
    """Return the IPv4 or IPv6 layer, or None for non-IP packets."""
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def get_ports(packet):
    """Return source and destination ports when TCP/UDP is present."""
    if TCP in packet:
        return packet[TCP].sport, packet[TCP].dport
    if UDP in packet:
        return packet[UDP].sport, packet[UDP].dport
    return "", ""


def get_dns_query(packet) -> str:
    """Return a DNS query name when available."""
    if DNS in packet and DNSQR in packet:
        try:
            query = packet[DNSQR].qname
            return query.decode("utf-8", errors="replace").rstrip(".")
        except (AttributeError, UnicodeError):
            return ""
    return ""


def ensure_csv_header() -> None:
    """Create the CSV file and header if the file does not exist or is empty."""
    if not CSV_FILE.exists() or CSV_FILE.stat().st_size == 0:
        with CSV_FILE.open("w", newline="", encoding="utf-8") as file:
            csv.writer(file).writerow(CSV_HEADERS)


def analyze_packet(packet) -> None:
    """Print and log metadata for each captured IP packet."""
    global total_packets

    ip = get_ip_layer(packet)
    if ip is None:
        return

    protocol = identify_protocol(packet)
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
