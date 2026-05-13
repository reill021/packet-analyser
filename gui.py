"""
Network Packet Analyser & IDS — GUI
Author: Ciarán Reilly
A Tkinter-based graphical interface for the packet analyser.
Run with: python3 gui.py
"""

import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime
import queue

from scapy.all import sniff, get_if_list
from rules.detector import ThreatDetector
from logger import AlertLogger

DARK_BG    = "#0a0e17"
SURFACE    = "#111827"
SURFACE2   = "#1a2436"
ACCENT     = "#00d4aa"
RED        = "#f87171"
YELLOW     = "#fbbf24"
GREEN      = "#34d399"
TEXT       = "#e2e8f0"
MUTED      = "#64748b"
FONT_MONO  = ("Courier", 10)
FONT_MAIN  = ("Helvetica", 10)
FONT_TITLE = ("Helvetica", 12, "bold")


class IDSGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyser & IDS — Ciarán Reilly")
        self.root.configure(bg=DARK_BG)
        self.root.geometry("1100x700")
        self.root.minsize(900, 600)

        self.alert_queue   = queue.Queue()
        self.packet_queue  = queue.Queue()
        self.running       = False
        self.sniff_thread  = None
        self.packet_count  = 0
        self.alert_count   = 0
        self.tcp_count     = 0
        self.udp_count     = 0
        self.icmp_count    = 0

        self.alert_logger  = AlertLogger("alerts/alerts.log")
        self.detector      = ThreatDetector(self.alert_logger)

        self._build_ui()
        self._poll_queues()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=SURFACE, pady=10)
        header.pack(fill=tk.X)
        tk.Label(header, text="  ■ NETWORK PACKET ANALYSER & IDS",
                 font=("Courier", 14, "bold"), fg=ACCENT, bg=SURFACE).pack(side=tk.LEFT)
        self.status_label = tk.Label(header, text="● IDLE",
                                     font=FONT_MONO, fg=MUTED, bg=SURFACE)
        self.status_label.pack(side=tk.RIGHT, padx=15)

        # Controls bar
        ctrl = tk.Frame(self.root, bg=DARK_BG, pady=8, padx=12)
        ctrl.pack(fill=tk.X)

        tk.Label(ctrl, text="Interface:", font=FONT_MAIN, fg=TEXT, bg=DARK_BG).pack(side=tk.LEFT)
        self.iface_var = tk.StringVar()
        interfaces = get_if_list()
        self.iface_combo = ttk.Combobox(ctrl, textvariable=self.iface_var,
                                         values=interfaces, width=14, state="readonly")
        self.iface_combo.pack(side=tk.LEFT, padx=(4, 12))
        if interfaces:
            self.iface_combo.set(interfaces[0])

        self.start_btn = tk.Button(ctrl, text="▶  Start Capture",
                                   command=self.start_capture,
                                   bg=ACCENT, fg=DARK_BG, font=("Helvetica", 10, "bold"),
                                   relief=tk.FLAT, padx=12, pady=4, cursor="hand2")
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = tk.Button(ctrl, text="■  Stop",
                                  command=self.stop_capture,
                                  bg=SURFACE2, fg=TEXT, font=FONT_MAIN,
                                  relief=tk.FLAT, padx=12, pady=4, cursor="hand2",
                                  state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        tk.Button(ctrl, text="📂  Load PCAP",
                  command=self.load_pcap,
                  bg=SURFACE2, fg=TEXT, font=FONT_MAIN,
                  relief=tk.FLAT, padx=12, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=4)

        tk.Button(ctrl, text="🗑  Clear",
                  command=self.clear_all,
                  bg=SURFACE2, fg=MUTED, font=FONT_MAIN,
                  relief=tk.FLAT, padx=12, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=4)

        # Stat cards
        stats_frame = tk.Frame(self.root, bg=DARK_BG, padx=12, pady=4)
        stats_frame.pack(fill=tk.X)

        self.stat_vars = {}
        cards = [
            ("PACKETS",  "total",  TEXT),
            ("TCP",      "tcp",    TEXT),
            ("UDP",      "udp",    TEXT),
            ("ICMP",     "icmp",   TEXT),
            ("ALERTS",   "alerts", RED),
        ]
        for label, key, colour in cards:
            card = tk.Frame(stats_frame, bg=SURFACE, padx=16, pady=8,
                            highlightbackground=ACCENT, highlightthickness=0)
            card.pack(side=tk.LEFT, padx=6, pady=4)
            tk.Label(card, text=label, font=("Courier", 9), fg=MUTED, bg=SURFACE).pack()
            var = tk.StringVar(value="0")
            self.stat_vars[key] = var
            tk.Label(card, textvariable=var, font=("Courier", 18, "bold"),
                     fg=colour, bg=SURFACE).pack()

        # Main panes
        paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL,
                               bg=DARK_BG, sashwidth=4, sashrelief=tk.FLAT)
        paned.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        # Left — packet log
        left = tk.Frame(paned, bg=SURFACE)
        paned.add(left, minsize=350)
        tk.Label(left, text="PACKET LOG", font=("Courier", 10, "bold"),
                 fg=ACCENT, bg=SURFACE, pady=6).pack(fill=tk.X)
        self.packet_log = scrolledtext.ScrolledText(
            left, bg=DARK_BG, fg=TEXT, font=("Courier", 9),
            insertbackground=TEXT, relief=tk.FLAT, state=tk.DISABLED)
        self.packet_log.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0,4))
        self.packet_log.tag_config("tcp",    foreground="#60a5fa")
        self.packet_log.tag_config("udp",    foreground="#a78bfa")
        self.packet_log.tag_config("icmp",   foreground="#fb923c")
        self.packet_log.tag_config("other",  foreground=MUTED)

        # Right — alerts
        right = tk.Frame(paned, bg=SURFACE)
        paned.add(right, minsize=350)

        alerts_header = tk.Frame(right, bg=SURFACE)
        alerts_header.pack(fill=tk.X)
        tk.Label(alerts_header, text="ALERTS FEED", font=("Courier", 10, "bold"),
                 fg=RED, bg=SURFACE, pady=6).pack(side=tk.LEFT, padx=8)

        # Filter buttons
        self.filter_var = tk.StringVar(value="ALL")
        for f in ["ALL", "HIGH", "MEDIUM", "LOW"]:
            colour = {"ALL": MUTED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}[f]
            tk.Radiobutton(alerts_header, text=f, variable=self.filter_var,
                           value=f, command=self._apply_filter,
                           fg=colour, bg=SURFACE, selectcolor=SURFACE2,
                           activebackground=SURFACE, font=("Courier", 9),
                           relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT)

        self.alert_tree = ttk.Treeview(right, columns=("time","sev","rule","src","detail"),
                                        show="headings", style="Dark.Treeview")
        self.alert_tree.heading("time",   text="Time")
        self.alert_tree.heading("sev",    text="Severity")
        self.alert_tree.heading("rule",   text="Rule")
        self.alert_tree.heading("src",    text="Source")
        self.alert_tree.heading("detail", text="Detail")
        self.alert_tree.column("time",   width=75,  stretch=False)
        self.alert_tree.column("sev",    width=70,  stretch=False)
        self.alert_tree.column("rule",   width=160, stretch=False)
        self.alert_tree.column("src",    width=130, stretch=False)
        self.alert_tree.column("detail", width=300)

        scrollbar = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscroll=scrollbar.set)
        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4,0), pady=(0,4))
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=(0,4))

        self.alert_tree.tag_configure("HIGH",   foreground=RED)
        self.alert_tree.tag_configure("MEDIUM", foreground=YELLOW)
        self.alert_tree.tag_configure("LOW",    foreground=GREEN)

        self._all_alerts = []

        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.Treeview", background=DARK_BG, foreground=TEXT,
                         fieldbackground=DARK_BG, rowheight=24, font=("Courier", 9))
        style.configure("Dark.Treeview.Heading", background=SURFACE2,
                         foreground=ACCENT, font=("Courier", 9, "bold"))
        style.map("Dark.Treeview", background=[("selected", SURFACE2)])

        # Status bar
        self.statusbar = tk.Label(self.root, text="Ready. Select an interface and click Start Capture.",
                                  font=("Courier", 9), fg=MUTED, bg=SURFACE, anchor=tk.W, pady=4)
        self.statusbar.pack(fill=tk.X, side=tk.BOTTOM)

    # ── Capture Logic ─────────────────────────────────────────────────────────

    def start_capture(self):
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="● LIVE", fg=GREEN)
        iface = self.iface_var.get() or None
        self.statusbar.config(text=f"Capturing on {iface or 'default interface'}...")
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(iface=iface, prn=self._handle_packet,
                                 store=False, stop_filter=lambda _: not self.running),
            daemon=True)
        self.sniff_thread.start()

    def stop_capture(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="● STOPPED", fg=RED)
        self.statusbar.config(text=f"Capture stopped. {self.packet_count} packets, {self.alert_count} alerts.")

    def load_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files","*.pcap *.cap"), ("All","*.*")])
        if not path: return
        self.statusbar.config(text=f"Analysing {path}...")
        threading.Thread(
            target=lambda: sniff(offline=path, prn=self._handle_packet, store=False),
            daemon=True).start()

    def _handle_packet(self, packet):
        self.packet_queue.put(packet)
        for alert in self.detector.analyse(packet):
            self.alert_queue.put(alert)

    def clear_all(self):
        self.packet_count = self.alert_count = self.tcp_count = self.udp_count = self.icmp_count = 0
        for v in self.stat_vars.values(): v.set("0")
        self.packet_log.config(state=tk.NORMAL)
        self.packet_log.delete("1.0", tk.END)
        self.packet_log.config(state=tk.DISABLED)
        for row in self.alert_tree.get_children(): self.alert_tree.delete(row)
        self._all_alerts.clear()

    # ── Queue Polling ─────────────────────────────────────────────────────────

    def _poll_queues(self):
        # Process up to 20 packets per poll cycle
        for _ in range(20):
            try:
                packet = self.packet_queue.get_nowait()
                self._display_packet(packet)
            except queue.Empty:
                break

        # Process all pending alerts
        while not self.alert_queue.empty():
            try:
                alert = self.alert_queue.get_nowait()
                self._display_alert(alert)
            except queue.Empty:
                break

        self.root.after(100, self._poll_queues)

    def _display_packet(self, packet):
        from scapy.all import IP, TCP, UDP, ICMP
        self.packet_count += 1
        self.stat_vars["total"].set(str(self.packet_count))

        if packet.haslayer(TCP):
            proto, tag = "TCP", "tcp"
            self.tcp_count += 1
            self.stat_vars["tcp"].set(str(self.tcp_count))
            src = f"{packet[IP].src}:{packet[TCP].sport}" if packet.haslayer(IP) else "?"
            dst = f"{packet[IP].dst}:{packet[TCP].dport}" if packet.haslayer(IP) else "?"
        elif packet.haslayer(UDP):
            proto, tag = "UDP", "udp"
            self.udp_count += 1
            self.stat_vars["udp"].set(str(self.udp_count))
            src = f"{packet[IP].src}:{packet[UDP].sport}" if packet.haslayer(IP) else "?"
            dst = f"{packet[IP].dst}:{packet[UDP].dport}" if packet.haslayer(IP) else "?"
        elif packet.haslayer(ICMP):
            proto, tag = "ICMP", "icmp"
            self.icmp_count += 1
            self.stat_vars["icmp"].set(str(self.icmp_count))
            src = packet[IP].src if packet.haslayer(IP) else "?"
            dst = packet[IP].dst if packet.haslayer(IP) else "?"
        else:
            proto, tag = "OTHER", "other"
            src, dst = "?", "?"

        now  = datetime.now().strftime("%H:%M:%S")
        line = f"[{now}] {proto:<5}  {src:<22} → {dst}\n"
        self.packet_log.config(state=tk.NORMAL)
        self.packet_log.insert(tk.END, line, tag)
        self.packet_log.see(tk.END)
        self.packet_log.config(state=tk.DISABLED)

    def _display_alert(self, alert):
        self._all_alerts.append(alert)
        self.alert_count += 1
        self.stat_vars["alerts"].set(str(self.alert_count))
        self._apply_filter()

    def _apply_filter(self):
        f = self.filter_var.get()
        for row in self.alert_tree.get_children():
            self.alert_tree.delete(row)
        for alert in self._all_alerts:
            if f == "ALL" or alert["severity"] == f:
                self.alert_tree.insert("", tk.END,
                    values=(alert["time"], alert["severity"], alert["rule"],
                            alert["src"], alert["detail"]),
                    tags=(alert["severity"],))
        # Scroll to latest
        rows = self.alert_tree.get_children()
        if rows:
            self.alert_tree.see(rows[-1])


def main():
    root = tk.Tk()
    app  = IDSGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()
