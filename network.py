from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff
import csv
from datetime import datetime

# CSV file setup
log_file = "packet_log.csv"
with open(log_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Protocol", "Source IP", "Destination IP", "Source Port", "Destination Port"])

# Packet analyzer function
def analyze_packet(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    protocol = None
    src_ip = dst_ip = src_port = dst_port = "-"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "Other"

        # Print packet summary to console
        print(f"[{timestamp}] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        # Save to CSV
        with open(log_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, protocol, src_ip, dst_ip, src_port, dst_port])

# Start sniffing (requires admin/root privileges)
print("Starting Packet Sniffer... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, store=False)
