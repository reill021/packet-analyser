"""
Threat Detector — all IDS detection rules.
"""

import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP

#spike
class ThreatDetector:
    def __init__(self, alert_logger):
        self.logger = alert_logger
        self._syn_tracker     = defaultdict(set)
        self._syn_timestamps  = defaultdict(list)
        self._brute_tracker   = defaultdict(list)
        self._icmp_tracker    = defaultdict(list)

        self.PORT_SCAN_THRESHOLD  = 5
        self.PORT_SCAN_WINDOW     = 30
        self.BRUTE_THRESHOLD      = 6
        self.BRUTE_WINDOW         = 30
        self.ICMP_FLOOD_THRESHOLD = 20
        self.ICMP_FLOOD_WINDOW    = 5

        self.BRUTE_PORTS      = {22: "SSH", 21: "FTP", 3389: "RDP", 23: "Telnet", 25: "SMTP"}
        self.SUSPICIOUS_PORTS = {4444: "Metasploit default", 1337: "Common backdoor",
                                 31337: "Back Orifice", 12345: "NetBus", 5900: "VNC"}

    def analyse(self, packet) -> list:
        if not packet.haslayer(IP):
            return []
        return [a for a in [
            self.rule_port_scan(packet),
            self.rule_brute_force(packet),
            self.rule_xmas_scan(packet),
            self.rule_null_scan(packet),
            self.rule_icmp_flood(packet),
            self.rule_suspicious_port(packet),
            self.rule_large_udp(packet),
        ] if a]

    def _is_syn(self, packet):
        """Check for SYN flag compatible with all Scapy versions."""
        flags = str(packet[TCP].flags)
        return 'S' in flags and 'A' not in flags

    def rule_port_scan(self, packet):
        if not packet.haslayer(TCP):
            return None
        if not self._is_syn(packet):
            return None
        src, dst_port, now = packet[IP].src, packet[TCP].dport, time.time()
        self._syn_timestamps[src] = [t for t in self._syn_timestamps[src] if now - t < self.PORT_SCAN_WINDOW]
        self._syn_timestamps[src].append(now)
        self._syn_tracker[src].add(dst_port)
        if len(self._syn_timestamps[src]) == 1:
            self._syn_tracker[src] = {dst_port}
        if len(self._syn_tracker[src]) >= self.PORT_SCAN_THRESHOLD:
            count = len(self._syn_tracker[src])
            self._syn_tracker[src].clear()
            return self.logger.log("HIGH", "Port Scan Detected", src, packet[IP].dst,
                                   f"{count} unique ports probed in {self.PORT_SCAN_WINDOW}s")
        return None

    def rule_brute_force(self, packet):
        if not packet.haslayer(TCP): return None
        dst_port = packet[TCP].dport
        if dst_port not in self.BRUTE_PORTS: return None
        src, now = packet[IP].src, time.time()
        key = (src, dst_port)
        self._brute_tracker[key] = [t for t in self._brute_tracker[key] if now - t < self.BRUTE_WINDOW]
        self._brute_tracker[key].append(now)
        if len(self._brute_tracker[key]) == self.BRUTE_THRESHOLD:
            return self.logger.log("HIGH", "Brute Force Attempt", src,
                                   f"{packet[IP].dst}:{dst_port}",
                                   f"{self.BRUTE_THRESHOLD} {self.BRUTE_PORTS[dst_port]} connections in {self.BRUTE_WINDOW}s")
        return None

    def rule_xmas_scan(self, packet):
        if not packet.haslayer(TCP): return None
        flags = str(packet[TCP].flags)
        if 'F' in flags and 'P' in flags and 'U' in flags:
            return self.logger.log("MEDIUM", "Xmas Scan", packet[IP].src,
                                   f"{packet[IP].dst}:{packet[TCP].dport}",
                                   "TCP FIN+PSH+URG flags — likely Nmap Xmas scan")
        return None

    def rule_null_scan(self, packet):
        if not packet.haslayer(TCP): return None
        if str(packet[TCP].flags) == '' or packet[TCP].flags == 0:
            return self.logger.log("MEDIUM", "NULL Scan", packet[IP].src,
                                   f"{packet[IP].dst}:{packet[TCP].dport}",
                                   "TCP NULL flags — likely stealth scan attempt")
        return None

    def rule_icmp_flood(self, packet):
        if not packet.haslayer(ICMP): return None
        src, now = packet[IP].src, time.time()
        self._icmp_tracker[src] = [t for t in self._icmp_tracker[src] if now - t < self.ICMP_FLOOD_WINDOW]
        self._icmp_tracker[src].append(now)
        if len(self._icmp_tracker[src]) == self.ICMP_FLOOD_THRESHOLD:
            return self.logger.log("MEDIUM", "ICMP Flood", src, packet[IP].dst,
                                   f"{self.ICMP_FLOOD_THRESHOLD} ICMP packets in {self.ICMP_FLOOD_WINDOW}s")
        return None

    def rule_suspicious_port(self, packet):
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)): return None
        layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        if layer.dport in self.SUSPICIOUS_PORTS:
            return self.logger.log("HIGH", "Suspicious Port", packet[IP].src,
                                   f"{packet[IP].dst}:{layer.dport}",
                                   f"Traffic to port {layer.dport} — {self.SUSPICIOUS_PORTS[layer.dport]}")
        return None

    def rule_large_udp(self, packet):
        if not packet.haslayer(UDP): return None
        size = len(packet[UDP].payload)
        if size > 512:
            return self.logger.log("LOW", "Large UDP Packet", packet[IP].src,
                                   f"{packet[IP].dst}:{packet[UDP].dport}",
                                   f"UDP payload {size} bytes (threshold: 512)")
        return None