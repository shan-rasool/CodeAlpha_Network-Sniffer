# Basic Network Sniffer

A professional, beginner-friendly **command-line network packet sniffer and analyzer** built in Python using **Scapy**. This project captures live network traffic on an authorized interface, analyzes packet structure, tracks protocol statistics, and can export captures to standard `.pcap` files for review in Wireshark.

> ⚠️ **This tool is for educational purposes and authorized network monitoring only.** See the [Security and Ethical Use Disclaimer](#security-and-ethical-use-disclaimer) below before using it.

---

## Table of Contents

1. [Internship Task Objective](#internship-task-objective)
2. [Features](#features)
3. [Technologies Used](#technologies-used)
4. [Project Structure](#project-structure)
5. [Installation Instructions](#installation-instructions)
6. [Dependency Installation](#dependency-installation)
7. [How to Run the Application](#how-to-run-the-application)
8. [Example Usage](#example-usage)
9. [Packet Fields Explained](#packet-fields-explained)
10. [PCAP Export Instructions](#pcap-export-instructions)
11. [Module Overview](#module-overview)
12. [Screenshots](#screenshots)
13. [Security and Ethical Use Disclaimer](#security-and-ethical-use-disclaimer)
14. [Limitations](#limitations)
15. [Future Improvements](#future-improvements)
16. [Author](#author)
17. [Internship Acknowledgment](#internship-acknowledgment)

---

## Internship Task Objective

This project was developed as part of a **CodeAlpha Cyber Security Internship Task**. The objective was to:

- Build a Python program capable of capturing live network traffic.
- Analyze captured packets to understand their structure and content.
- Demonstrate how data flows through a network and the basics of common network protocols (TCP, UDP, ICMP, ARP).
- Use safe, well-established Python packet-capture libraries (Scapy).
- Present captured information in a clean, readable, and professional format suitable for demonstration during an internship evaluation.

---

## Features

- **Live Packet Capture** — capture packets in real time, with interface selection, a configurable packet count, or unlimited continuous capture (stoppable with `Ctrl+C`).
- **Detailed Packet Analysis** — displays packet number, timestamp, source/destination IP, protocol, length, source/destination ports, TCP flags, and ICMP type/code.
- **Protocol Recognition** — TCP, UDP, ICMP, ARP, and a catch-all "Other/Unknown" category.
- **Live Protocol Statistics** — running counts of total, TCP, UDP, ICMP, ARP, and other packets, with a full summary printed when capture stops.
- **Optional Payload Inspection** — safely previews readable payload bytes (length-limited, non-printable bytes masked), and never attempts to decrypt encrypted traffic.
- **Packet Filtering** — filter live captures by protocol, source IP, destination IP, or port, with input validation and helpful error messages.
- **PCAP Export** — save captured packets to a standard `.pcap` file (auto-creates the `captures/` folder, timestamped filenames), fully compatible with Wireshark.
- **Clean Terminal Menu Interface** — professional, numbered menu designed for easy live demonstration.
- **Robust Error Handling** — friendly messages instead of raw Python stack traces for missing dependencies, permission issues, invalid interfaces, invalid filters, and more.

---

## Technologies Used

- **Python 3** (3.8+)
- **[Scapy](https://scapy.net/)** — packet crafting, sniffing, and PCAP I/O
- Standard library modules: `os`, `re`, `string`, `datetime`, `dataclasses`

---

## Project Structure

```text
CodeAlpha_BasicNetworkSniffer/
│
├── main.py                  # Application entry point & interactive menu
├── requirements.txt         # Python dependencies
├── README.md                # Project documentation (this file)
├── LICENSE                  # MIT License
├── .gitignore                # Git ignore rules
│
├── src/
│   ├── __init__.py
│   ├── sniffer.py            # Core live capture engine (Scapy wrapper)
│   ├── packet_analyzer.py    # Per-packet field extraction & formatting
│   ├── filters.py            # Optional protocol/IP/port filtering
│   ├── statistics.py         # Live protocol statistics tracking
│   └── utils.py               # Shared helpers: formatting, validation, I/O
│
├── captures/                 # Saved .pcap files (auto-created)
│   └── .gitkeep
│
└── screenshots/               # Screenshots for documentation/portfolio
    └── .gitkeep
```

---

## Installation Instructions

### 1. Clone the repository

```bash
git clone <repository-url>
cd CodeAlpha_BasicNetworkSniffer
```

### 2. (Recommended) Create a virtual environment

```bash
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

---

## Dependency Installation

Install all required dependencies:

```bash
pip install -r requirements.txt
```

### Windows-specific requirement: Npcap

Scapy relies on a packet-capture driver to sniff live traffic. On **Windows**, you must install **[Npcap](https://npcap.com/#download)** (the modern replacement for WinPcap) before live capture will work:

1. Download and run the Npcap installer from https://npcap.com/#download
2. During installation, check **"Install Npcap in WinPcap API-compatible Mode"**.
3. Restart your terminal after installation.

On **Linux/macOS**, packet capture typically works out of the box using the system's native raw-socket capabilities, but requires elevated privileges (see below).

---

## How to Run the Application

### Windows

Run your terminal **as Administrator**, then:

```bash
python main.py
```

### Linux / macOS

Live packet capture requires raw socket access, so run with elevated privileges:

```bash
sudo python3 main.py
```

> Without elevated/administrator privileges, live capture will fail with a clear permission error message rather than crashing.

---

## Example Usage

```text
=========================================
       BASIC NETWORK SNIFFER
=========================================

==========================================
  DISCLAIMER
==========================================
This project is intended only for educational purposes and authorized
network monitoring. Do not capture or inspect traffic on networks or
systems without explicit permission.
==========================================


1. Start Live Packet Capture
2. Capture Specific Number of Packets
3. Configure Packet Filter
4. View Available Network Interfaces
5. Enable/Disable Payload Inspection
6. Save Capture to PCAP
7. View Statistics
8. Exit

Enter your choice: 2
Enter interface name (leave blank for default):
Number of packets to capture: 5
[INFO] Starting capture on interface: default | Count: 5 | No filter active (capturing all supported protocols).
------------------------------------------------------------
Packet #1  |  2026-08-24 10:15:02.481
  Protocol   : TCP
  Length     : 66 bytes
  Source IP      : 192.168.1.12
  Destination IP : 142.250.72.14
  Source Port      : 51422
  Destination Port : 443
  TCP Flags  : SYN
------------------------------------------------------------
Packet #2  |  2026-08-24 10:15:02.512
  Protocol   : ARP
  Length     : 42 bytes
  Source IP      : 192.168.1.1
  Destination IP : 192.168.1.12
------------------------------------------------------------
...
[OK] Capture complete. 5 packet(s) captured.
==========================================
           CAPTURE STATISTICS SUMMARY
==========================================
Total Packets Captured : 5
  TCP Packets   : 3
  UDP Packets   : 1
  ICMP Packets  : 0
  ARP Packets   : 1
  Other Packets : 0
Total Data Captured     : 312 B
==========================================
```

---

## Packet Fields Explained

| Field | Description |
|---|---|
| **Packet Number** | Sequential index of the packet within the current capture session. |
| **Timestamp** | Local date/time the packet was captured, to millisecond precision. |
| **Source IP** | The IP address the packet originated from. |
| **Destination IP** | The IP address the packet was sent to. |
| **Protocol** | TCP, UDP, ICMP, ARP, or OTHER (unrecognized/unsupported protocol). |
| **Length** | Total size of the packet in bytes. |
| **Source Port / Destination Port** | Applicable only to TCP/UDP; identifies the sending/receiving application. |
| **TCP Flags** | Decoded TCP control flags (e.g. SYN, ACK, FIN, PSH, RST, URG). |
| **ICMP Type/Code** | Numeric ICMP message type and code (e.g. type 8 = Echo Request / "ping"). |
| **Payload** | A safe, length-limited, readable preview of packet data (only shown when payload inspection is enabled). Non-printable bytes are masked, and encrypted/unavailable payloads are clearly labeled — the tool never attempts decryption. |

---

## PCAP Export Instructions

1. Run one or more capture sessions (menu option 1 or 2) so that packets are buffered in memory.
2. Select **option 6 — "Save Capture to PCAP"** from the main menu.
3. Optionally enter a custom filename, or press Enter to auto-generate one using the pattern:

   ```text
   captures/capture_YYYYMMDD_HHMMSS.pcap
   ```

   Example: `captures/capture_20260824_101502.pcap`

4. The `captures/` directory is created automatically if it doesn't already exist.
5. Open the resulting `.pcap` file directly in **[Wireshark](https://www.wireshark.org/)** for deeper protocol analysis.

---

## Module Overview

- **`main.py`** — The application's entry point. Renders the terminal menu, routes user choices to the appropriate handler functions, and wraps every action in error handling so the program never crashes into a raw traceback.
- **`src/sniffer.py`** — The core capture engine. Wraps Scapy's `sniff()` function, manages the capture session (packet buffer, statistics, active filter, payload-inspection toggle), lists available interfaces, and exports captures to `.pcap` via `wrpcap()`.
- **`src/packet_analyzer.py`** — Inspects each raw Scapy packet layer-by-layer (ARP, IP, TCP, UDP, ICMP, Raw) and produces a structured `PacketInfo` object with all display-ready fields, including a safely-rendered payload preview.
- **`src/filters.py`** — Defines the `PacketFilter` data structure and interactive configuration flow. Supports both post-capture matching (`matches()`) and conversion to a BPF filter string (`to_bpf_string()`) for efficient kernel-level filtering during `sniff()`.
- **`src/statistics.py`** — Tracks running per-protocol packet counts and total bytes captured, and renders a clean summary report at the end of a session.
- **`src/utils.py`** — Shared helpers: terminal banners/menus, timestamp formatting, safe payload rendering, byte-size formatting, IP/port/protocol validation, and directory creation.

---

## Screenshots

> Add screenshots of the running application here for your GitHub repository / portfolio / LinkedIn video. Suggested shots:

- `screenshots/01_main_menu.png` — the main menu on startup
- `screenshots/02_live_capture.png` — a live capture session in progress
- `screenshots/03_statistics_summary.png` — the statistics summary after stopping a capture
- `screenshots/04_filter_configuration.png` — configuring a protocol/IP/port filter
- `screenshots/05_pcap_export.png` — saving a capture to `.pcap` and the confirmation message
- `screenshots/06_wireshark_open.png` — the exported `.pcap` file opened in Wireshark

---

## Security and Ethical Use Disclaimer

> This project is intended only for educational purposes and authorized network monitoring. Do not capture or inspect traffic on networks or systems without explicit permission.

This tool:

- Is designed for use on **your own computer**, a **lab/test environment**, or a network where you have **explicit, documented permission** to monitor traffic.
- Does **not** include any features for credential theft, stealthy/covert interception, bypassing security controls, or unauthorized surveillance.
- Never attempts to decrypt encrypted payloads; it only displays what is already visible on the wire.
- Should be used in compliance with all applicable local laws, organizational policies, and terms of service.

Unauthorized network interception may be illegal in your jurisdiction. **You are solely responsible for ensuring you have proper authorization before running this tool on any network.**

---

## Limitations

- Requires elevated/administrator privileges to perform live packet capture (an inherent OS/driver requirement, not a design flaw).
- On Windows, requires the Npcap driver to be installed separately.
- Payload inspection shows only a truncated, readable preview — it is not a full protocol reconstruction tool (e.g. it does not reassemble TCP streams or reconstruct files).
- IPv6 addresses are captured at the IP-layer level but detailed IPv6-specific extension headers are not separately parsed.
- Designed for learning and demonstration; not intended to replace production-grade tools like Wireshark or tcpdump for professional network forensics.

---

## Future Improvements

- Add a graphical user interface (GUI) or web dashboard for live visualization.
- Support TCP stream reassembly for more complete payload/session viewing.
- Add geolocation lookups for public IP addresses.
- Add alerting/notification rules (e.g. flag unusual traffic spikes or port-scan patterns).
- Support reading and re-analyzing existing `.pcap` files, not just live capture.
- Add automated unit tests and CI integration.

---

## Author

**[Your Name Here]**
Cyber Security Intern — CodeAlpha
[Your GitHub Profile / LinkedIn / Portfolio Link]

---

## Internship Acknowledgment

This project, **BasicNetworkSniffer**, was developed as part of the **CodeAlpha Cyber Security Internship Program**, fulfilling the task requirements to build a live network packet sniffer and analyzer using Python and Scapy for educational and authorized-use purposes.
