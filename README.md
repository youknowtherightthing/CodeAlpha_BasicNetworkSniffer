# CodeAlpha Basic Network Sniffer

A Python-based network packet sniffer built using **Scapy**, developed as part of the
CodeAlpha Cyber Security Internship (Task 1).

## 📖 Overview

This tool captures live network traffic on a system and displays key information about
each packet in real time, including:

- Source IP address
- Destination IP address
- Protocol (TCP, UDP, ICMP, etc.)
- Packet length
- Source/Destination ports (for TCP/UDP)
- A short preview of the packet payload

The goal of this project is to understand how data flows across a network, how packets
are structured, and how basic protocol analysis works — the same principles behind
tools like Wireshark.

## 🛠 Technologies Used

- Python 3
- [Scapy](https://scapy.net/) — for packet capture and parsing

## ⚙️ Setup Instructions

### 1. Install dependencies
```bash
pip install scapy
```

### 2. Windows users only
Install [Npcap](https://npcap.com/#download) (required for packet capture on Windows).
During installation, enable **"Install Npcap in WinPcap API-compatible Mode."**

### 3. Run the sniffer
Because packet capture requires elevated privileges:

**Windows** (run terminal as Administrator):
```bash
python sniffer.py
```

**Linux/Mac:**
```bash
sudo python3 sniffer.py
```

## 🚀 Usage

```bash
python sniffer.py                     # Capture all IP traffic indefinitely
python sniffer.py -c 20               # Capture 20 packets then stop
python sniffer.py -i "Wi-Fi"          # Capture on a specific interface
python sniffer.py -f "tcp port 80"    # Apply a custom BPF filter
```

## 📊 Sample Output[14:05:24]  14.102.231.202 -> 10.206.174.26   | Proto: TCP  | Len: 1398 bytes | Sport: 80 Dport: 56437
Payload preview: b'HTTP/1.1 206 Partial Content...'
[14:05:24]   10.206.174.26 -> 14.102.231.202  | Proto: TCP  | Len: 54 bytes   | Sport: 56437 Dport: 80
## 🔍 What I Learned

- How IP packets are structured and how source/destination addressing works
- The difference between TCP, UDP, and ICMP traffic patterns
- How TCP handshakes and ACKs appear at the packet level
- Why most modern web traffic (HTTPS/TLS) shows encrypted, unreadable payloads
- How BPF filters can be used to narrow down capture scope

## ⚠️ Disclaimer

This tool is built strictly for educational purposes as part of the CodeAlpha
Cyber Security Internship. Only use it on networks you own or have explicit
permission to monitor.

## 👤 Author

Built by **Dharmesh Godhaniya** as part of the **CodeAlpha Cyber Security Internship**.