from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from datetime import datetime
import csv
import os

packets_data = []

csv_file = "captures/packets.csv"

os.makedirs("captures", exist_ok=True)

if not os.path.exists(csv_file):
    with open(csv_file, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port",
            "Length"
        ])

def packet_callback(packet):

    protocol = "OTHER"
    src_ip = "-"
    dst_ip = "-"
    src_port = "-"
    dst_port = "-"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if ARP in packet:
        protocol = "ARP"

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

    packet_info = {
        "timestamp": timestamp,
        "src": src_ip,
        "dst": dst_ip,
        "protocol": protocol,
        "sport": src_port,
        "dport": dst_port,
        "length": len(packet)
    }

    packets_data.append(packet_info)

    with open(csv_file, "a", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            len(packet)
        ])

def start_sniffing():
    sniff(
        prn=packet_callback,
        store=False
    )