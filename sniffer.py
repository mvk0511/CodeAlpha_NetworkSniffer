from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Identify protocol
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = bytes(packet[TCP].payload)[:50]
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = bytes(packet[UDP].payload)[:50]
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = dst_port = "-"
            payload = b""
        else:
            protocol = f"OTHER({proto})"
            src_port = dst_port = "-"
            payload = b""

        print(f"[{timestamp}] {protocol}")
        print(f"  SRC: {src_ip}:{src_port}  →  DST: {dst_ip}:{dst_port}")
        if payload:
            print(f"  PAYLOAD: {payload}")
        print("-" * 60)

print("🔍 Network Sniffer Started... (Press Ctrl+C to stop)\n")
sniff(prn=packet_callback, store=False, count=50)  # captures 50 packets