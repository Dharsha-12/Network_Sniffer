# 🔍 Basic Network Sniffer

> **CodeAlpha Cybersecurity Internship — Task 1**

A raw socket-based network packet sniffer built in pure Python. Captures and analyzes live network traffic, displaying Ethernet frames, IPv4 packets, TCP/UDP segments, and ICMP messages in a readable format — no external libraries required.

---

## 📸 Sample Output

```
============================================================
        BASIC NETWORK SNIFFER
        CodeAlpha Internship - Task 1
============================================================

[*] Sniffing started... Press Ctrl+C to stop.

============================================================
  Packet #1  |  Time: 14:32:05
============================================================

[ETHERNET FRAME]
	 - Destination MAC : FF:FF:FF:FF:FF:FF
	 - Source MAC      : A4:C3:F0:85:71:2B
	 - Protocol        : 8

[IPv4 PACKET]
		 - Version         : 4
		 - Header Length   : 20 bytes
		 - TTL             : 64
		 - Source IP       : 192.168.1.5
		 - Destination IP  : 8.8.8.8

[UDP SEGMENT]
			 - Source Port      : 54321
			 - Destination Port : 53
			 - Length           : 40
			 - Payload:
				query..
```

---

## ✨ Features

- **Ethernet Frame Parsing** — Extracts source/destination MAC addresses and EtherType
- **IPv4 Packet Decoding** — Version, TTL, protocol, source/destination IPs
- **TCP Segment Analysis** — Ports, sequence numbers, all 6 TCP flags (SYN, ACK, FIN, RST, PSH, URG)
- **UDP Segment Analysis** — Ports, length, and payload
- **ICMP Packet Decoding** — Type, code, checksum, and data
- **Readable Payload Display** — Non-printable bytes shown as `.` for clean output
- **Live Packet Counter + Timestamp** — Every packet is numbered and timestamped
- **Zero External Dependencies** — Uses only Python built-in libraries

---

## 🛠️ Requirements

| Requirement | Detail |
|---|---|
| OS | **Linux only** (uses `AF_PACKET` raw sockets) |
| Python | Python 3.6+ |
| Privileges | Must be run as **root** (`sudo`) |
| Libraries | None — only Python standard library |

> **Windows/macOS users:** Raw `AF_PACKET` sockets are Linux-specific. Use [Scapy](https://scapy.net/) as an alternative on other platforms.

---

## 🚀 Installation & Usage

### 1. Clone the repository

```bash
git clone https://github.com/YourUsername/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
```

### 2. (Optional) Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Run the sniffer

```bash
sudo python3 network_sniffer.py
```

### 4. Stop capturing

Press `Ctrl + C` — the sniffer will print the total number of packets captured and exit cleanly.

---

## 📁 Project Structure

```
CodeAlpha_NetworkSniffer/
│
├── network_sniffer.py     # Main sniffer script
├── requirements.txt       # Dependencies (none required)
├── README.md              # Project documentation
├── .gitignore             # Git ignore rules
└── LICENSE                # MIT License
```

---

## 🔬 How It Works

```
Raw Network Interface
        │
        ▼
  Ethernet Frame      ← MAC addresses, EtherType
        │
        ▼
   IPv4 Packet        ← IPs, TTL, protocol number
        │
   ┌────┼────┐
   ▼    ▼    ▼
  TCP  UDP  ICMP      ← Ports, flags, payload
```

Each captured packet travels through a chain of parsers using Python's `struct.unpack()` to decode raw bytes according to standard protocol header formats (RFC 791, RFC 793, RFC 768, RFC 792).

---
