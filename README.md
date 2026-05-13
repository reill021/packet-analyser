# Network Packet Analyser & IDS

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

A Python-based Network Intrusion Detection System (IDS) that captures live network traffic and applies detection rules to identify suspicious activity in real time.

Available in two modes — a **graphical desktop GUI** (Tkinter) and a **terminal dashboard** (Rich). Built as part of a cybersecurity portfolio demonstrating skills in network security, packet analysis, and threat detection.

---

## Features

- **Live packet capture** using Scapy on any network interface
- **7 detection rules** covering the most common network-based attacks:
  - SYN port scan detection
  - Brute force attempts (SSH, FTP, RDP, Telnet, SMTP)
  - Xmas scan detection (Nmap fingerprinting)
  - NULL scan detection
  - ICMP flood detection
  - Suspicious/backdoor port traffic
  - Oversized UDP packet detection (DNS amplification / data exfiltration)
- **Graphical GUI** — interface selector, live packet log, filterable alerts feed, stat counters
- **Terminal dashboard** — fallback Rich-powered CLI dashboard
- **Dual alert logging** — human-readable `.log` and machine-readable `.json` (SIEM-compatible)
- **Offline pcap analysis** — load and replay `.pcap` files through the IDS engine

---

## Project Structure

```
packet-analyser/
├── gui.py               # Graphical UI (Tkinter) — recommended
├── analyser.py          # Terminal dashboard (Rich)
├── logger.py            # Alert logger (.log + .json output)
├── rules/
│   └── detector.py      # All 7 IDS detection rules
├── alerts/              # Alert output (auto-created on first run)
├── requirements.txt
└── README.md
```

---

## Installation

### Kali Linux (recommended)

```bash
git clone https://github.com/YOUR-USERNAME/packet-analyser.git
cd packet-analyser

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

> **Kali tip:** Tkinter is usually pre-installed. If not:
> ```bash
> sudo apt install python3-tk -y
> ```

---

## Usage

### Graphical GUI (recommended)

```bash
sudo python3 gui.py
```

1. Select your network interface from the dropdown
2. Click **▶ Start Capture** to begin
3. Watch packets appear in the left panel in real time
4. Alerts appear in the right panel — filter by HIGH / MEDIUM / LOW
5. Click **📂 Load PCAP** to analyse a saved capture file

### Terminal dashboard

```bash
sudo python3 analyser.py
sudo python3 analyser.py -i eth0
python3 analyser.py --pcap capture.pcap
```

### Testing on Kali with Nmap

```bash
# Terminal 1 — start the IDS
sudo python3 gui.py

# Terminal 2 — trigger detection rules
nmap -sS localhost        # triggers port scan detection
nmap -sX localhost        # triggers Xmas scan detection
ping -f localhost         # triggers ICMP flood detection
```

---

## Detection Rules

| Rule | Severity | Description |
|---|---|---|
| Port Scan | HIGH | 15+ unique SYN packets from one source in 10s |
| Brute Force | HIGH | 6+ connections to SSH/FTP/RDP in 30s |
| Xmas Scan | MEDIUM | TCP FIN+PSH+URG flags set simultaneously |
| NULL Scan | MEDIUM | TCP packet with no flags set |
| ICMP Flood | MEDIUM | 20+ ICMP packets from one source in 5s |
| Suspicious Port | HIGH | Traffic to known backdoor ports (4444, 1337, etc.) |
| Large UDP | LOW | UDP payload exceeding 512 bytes |

Thresholds are configurable in `rules/detector.py`.

---

## Alert Output

**alerts/alerts.log** — human-readable:
```
2025-05-14 14:32:01 | ERROR | [HIGH] Rule=Port Scan Detected | Src=192.168.1.42 | Dst=192.168.1.1
```

**alerts/alerts.json** — SIEM-compatible:
```json
[
  {
    "timestamp": "2025-05-14T14:32:01.123456",
    "severity": "HIGH",
    "rule": "Port Scan Detected",
    "src": "192.168.1.42",
    "dst": "192.168.1.1",
    "detail": "15 unique ports probed in 10s window"
  }
]
```

---

## Roadmap

- [x] 7 detection rules
- [x] Tkinter graphical GUI with live packet log and alert feed
- [x] Terminal dashboard mode
- [x] Dual alert logging (.log + .json)
- [x] Offline pcap analysis
- [ ] Screenshots from Kali Linux testing
- [ ] Custom rule configuration via YAML
- [ ] Email/webhook alerting

---

## Legal Notice

For use only on networks you own or have explicit permission to monitor. Unauthorised packet capture may be illegal in your jurisdiction.

---

## Author

**Ciarán Reilly** — MSc Software Design with Cyber Security | CompTIA Security+ | CEH
[LinkedIn](https://linkedin.com/in/YOUR-USERNAME) · [GitHub](https://github.com/YOUR-USERNAME)
