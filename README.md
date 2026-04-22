# ⬡ NetPhantom v2.0 — Professional Network Packet Sniffer


---

```
  ███╗   ██╗███████╗████████╗    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██║╚██╗██║██╔══╝     ██║       ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║ ╚████║███████╗   ██║       ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
                                                          NetPhantom
```

---

## 📁 Project Structure

```
nETWORK pACKATE/
├── main.py          ← Entry point: mode selector (GUI / CLI)
├── capture.py       ← Packet capture engine (Scapy + threading)
├── analyzer.py      ← Packet parser + threat detection engine
├── gui.py           ← Hacker-style Tkinter GUI dashboard
├── requirements.txt ← Python dependencies
└── README.md        ← This file
```

---

## ⚙️ Installation

### 1. Prerequisites
- Python 3.10+
- **Windows**: [Npcap](https://npcap.com/) installed (required by Scapy for packet capture)
- **Linux/macOS**: `libpcap` (usually pre-installed)

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

> `scapy` — Packet sniffing engine  
> `colorama` — Terminal color output (CLI mode)

### 3. Privileges (REQUIRED for full capture)

| Platform | How to Run |
|----------|------------|
| Windows  | Right-click terminal → **Run as Administrator** |
| Linux    | `sudo python main.py ...` |
| macOS    | `sudo python main.py ...` |

---

## 🚀 Usage

### 🖥️ GUI Mode (Default)

```bash
python main.py
# or explicitly:
python main.py --mode gui
```

Launches the full **dark hacker-style NetPhantom dashboard** with:
- Live packet capture table
- Real-time protocol stats
- Threat alerts panel
- Search & filter
- One-click export (PCAP / JSON)

---


---

## 🎨 GUI Dashboard Features

| Panel | Description |
|-------|-------------|
| **Control Bar** | Select interface, set BPF filter, Start/Stop capture |
| **Packet Table** | Live scrolling table: Time, Src, Dst, Protocol, Length, Info |
| **Details Panel** | Click any row to see full packet breakdown |
| **Stats Panel** | Total packets, PPS, protocol counters, bar chart |
| **Alerts Panel** | Real-time threat detection alerts |

### ⌨️ GUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `F5` | Start capture |
| `F6` | Stop capture |
| `Ctrl+E` | Open export dialog |
| `Ctrl+F` | Focus search box |
| `Ctrl+L` | Clear all packets |
| `Escape` | Stop capture |
| `Double-click row` | Open full packet detail popup |

### 🎨 Color Coding

| Color | Protocol |
|-------|----------|
| 🟢 Green | TCP |
| 🔵 Blue | UDP |
| 🟡 Yellow | ICMP |
| 🟣 Purple | ARP |
| 🩵 Cyan | DNS |
| ⬜ White | IPv6 |
| 🔴 Red | Suspicious/Alert packets |

---

## 🔐 Threat Detection (Built-in)

| Threat | Detection Threshold |
|--------|---------------------|
| **Port Scan** | > 15 unique dst ports from one IP |
| **DoS / High Traffic** | > 100 packets/sec from one IP |
| **ICMP Flood** | > 50 ICMP packets/sec from one IP |
| **DNS Flood** | > 30 DNS queries/sec from one IP |

Alerts appear in both the GUI Alerts Panel and in CLI as red warning lines.

---

## 📦 Export Formats

| Format | Description |
|--------|-------------|
| `.pcap` | Standard packet capture (open in Wireshark) |
| `.json` | Parsed packet summaries (for scripting/analysis) |

```bash
# CLI: auto-save pcap during capture
python main.py --mode cli -i eth0 -s output.pcap

# GUI: use Ctrl+E → choose PCAP or JSON
```

---

## 🧠 Architecture

```
main.py  (NetPhantom Entry Point)
  ├─ parse_arguments()   → argparse
  ├─ check_privileges()  → admin/root check
  ├─ --mode gui          → gui.py → PacketSnifferGUI
                                    │
                              capture.py → CaptureEngine
                                    │        ├─ sniff() [background thread]
                                    │        ├─ Queue<pkt_info>
                                    │        └─ export_pcap / export_json
                                    │
                              analyzer.py → PacketAnalyzer
                                             ├─ parse(pkt) → dict
                                             ├─ get_stats() → dict
                                             └─ _detect_threats() → alert str
```

### Threading Model

```
Main Thread              Capture Thread (daemon)
──────────               ──────────────────────
GUI poll_packets()  ←    scapy.sniff() → _packet_callback()
  (every 80ms)               ↓
  reads from Queue    → PacketAnalyzer.parse()
  updates Treeview        ↓
  updates Stats       → queue.put_nowait(pkt_info)
```

---

## 🛡️ Security & Ethics

> **⚠ Warning: Only use this tool on networks you own or have explicit written permission to monitor.**
>
> Unauthorized packet sniffing is illegal under:
> - US Computer Fraud and Abuse Act (CFAA)
> - UK Computer Misuse Act
> - EU Directive 2013/40/EU
> - And equivalent laws worldwide

This tool is built for:
- ✅ Authorized penetration testing
- ✅ Network troubleshooting on your own network
- ✅ Cybersecurity education and learning
- ✅ CTF/lab environments
- ❌ NOT for unauthorized surveillance

---

## 🧪 Testing (Lab Setup)

```bash
# Generate test traffic (from another terminal)
ping 8.8.8.8

# On Linux: generate TCP traffic
curl http://example.com

# DNS test
nslookup google.com
```

---

## 🐛 Troubleshooting

| Issue | Fix |
|-------|-----|
| `Permission denied` | Run as Administrator (Windows) or `sudo` (Linux) |
| No packets captured | Install Npcap (Windows) or check interface name |
| `Interface not found` | Run `python main.py -l` to list available interfaces |
| Scapy import error | `pip install scapy` |
| GUI doesn't open | Ensure `tkinter` is installed (`python -m tkinter`) |
| High CPU usage | Reduce BPF filter scope, or use `--filter tcp` |

---

## 📋 Requirements

```
Python >= 3.10
scapy >= 2.5.0
colorama >= 0.4.6
tkinter (bundled with Python)
Npcap (Windows only) — https://npcap.com
```

---

## 👨‍💻 Author

**Lucky** — Ethical Hacker
Built as a demonstration of network security tooling, combining:
- Real-time packet capture (Scapy)
- Multi-threaded architecture
- Professional GUI design (Tkinter)
- CLI utility design patterns

**Tool Name: NetPhantom**

## 📜 License

This project is licensed under the Apache License 2.0.
See the LICENSE file for details.
---

*"With great packet-sniffing power comes great responsibility."*
