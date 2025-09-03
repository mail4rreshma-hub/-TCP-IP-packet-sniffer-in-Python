# 🐍 TCP/IP Packet Sniffer (Python + Scapy)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

A lightweight **TCP/IP Packet Sniffer** built in Python using [Scapy](https://scapy.net/).  
It captures live network traffic and displays details such as **Source IP, Destination IP, Protocol, and Length**.  
You can also log the packets into a CSV file for later analysis.  

---

## ⚡ Features
- Capture live TCP, UDP, and ICMP packets
- Extract source/destination IP and ports
- Real-time console logging
- Optional CSV export
- Cross-platform support (Linux & Windows with Npcap)

---

## 🛠️ Installation & Setup

### 1. Clone the repo
```bash
git clone https://github.com/your-username/tcp-sniffer.git
cd tcp-sniffer
