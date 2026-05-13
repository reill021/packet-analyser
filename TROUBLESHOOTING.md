cd ~/Desktop/projects\ 2026/packet-analyser
cat > TROUBLESHOOTING.md << 'EOF'
# Troubleshooting Notes

Real issues encountered and fixed during development and testing on Kali Linux.

## Issue 1 — Scapy SYN Flag Detection
**Problem:** IDS was capturing packets but not triggering port scan alerts.  
**Cause:** Scapy 2.7.0 returns TCP flags as strings (e.g. `'S'`) not integers (`0x02`).  
**Fix:** Changed flag comparison from `packet[TCP].flags == 0x02` to `'S' in str(packet[TCP].flags) and 'A' not in str(packet[TCP].flags)`.

## Issue 2 — Interface Not Found
**Problem:** `ValueError: Interface 'any' not found`  
**Cause:** Kali does not support `any` as an interface name in this Scapy version.  
**Fix:** Use `wlan0` for WiFi or `eth0` for wired. Run `ip a` to find your active interface.

## Issue 3 — Permission Denied on .pyc Files
**Problem:** `find: cannot delete .pyc: Permission denied`  
**Cause:** Cache files were created by sudo, so normal user cannot delete them.  
**Fix:** Use `sudo find . -name "*.pyc" -delete`

## Issue 4 — Scanning localhost Not Triggering Alerts
**Problem:** Nmap scans against `127.0.0.1` were not detected.  
**Cause:** Loopback interface `lo` does not pass SYN packets the same way as a real interface.  
**Fix:** Scan your actual network IP (`192.168.0.x`) and listen on `wlan0` instead.

## Issue 5 — Tkinter Not Installed
**Problem:** `ModuleNotFoundError: No module named 'tkinter'`  
**Cause:** Tkinter is a system package, not installable via pip.  
**Fix:** `sudo apt install python3-tk -y`

## Tested On
- Kali Linux 2026
- Python 3.13
- Scapy 2.7.0
- Nmap 7.95
EOF
