"""
Network Packet Analyser & IDS
Author: Ciarán Reilly
Description: Captures live network traffic and detects suspicious patterns
             including port scans, brute force attempts, and anomalous traffic.
"""

import time
import argparse
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich import box

from rules.detector import ThreatDetector
from logger import AlertLogger

console = Console()


def build_dashboard(stats: dict, alerts: list) -> Panel:
    """Build the live terminal dashboard."""

    stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    stats_table.add_column("Metric", style="bold cyan")
    stats_table.add_column("Value", style="white")
    stats_table.add_row("Packets captured", str(stats["total"]))
    stats_table.add_row("TCP packets",       str(stats["tcp"]))
    stats_table.add_row("UDP packets",       str(stats["udp"]))
    stats_table.add_row("ICMP packets",      str(stats["icmp"]))
    stats_table.add_row("Alerts triggered",  f"[bold red]{stats['alerts']}[/]")
    stats_table.add_row("Uptime",            stats["uptime"])
    stats_panel = Panel(stats_table, title="[bold cyan]Traffic Stats[/]", border_style="cyan")

    alert_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    alert_table.add_column("Time",     style="dim",       width=10)
    alert_table.add_column("Severity", style="bold",      width=10)
    alert_table.add_column("Rule",     style="cyan",      width=22)
    alert_table.add_column("Source",   style="white",     width=18)
    alert_table.add_column("Details",  style="dim white")

    for alert in alerts[-10:]:
        colour = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(alert["severity"], "white")
        alert_table.add_row(
            alert["time"],
            f"[{colour}]{alert['severity']}[/]",
            alert["rule"],
            alert["src"],
            alert["detail"],
        )
    alerts_panel = Panel(alert_table, title="[bold red]Recent Alerts[/]", border_style="red")

    return Panel(
        Columns([stats_panel, alerts_panel], equal=False, expand=True),
        title="[bold white] Network Packet Analyser & IDS  |  Ciarán Reilly[/]",
        border_style="bright_black",
    )


def main():
    parser = argparse.ArgumentParser(description="Network Packet Analyser & IDS")
    parser.add_argument("-i", "--interface", default=None,  help="Network interface (default: auto)")
    parser.add_argument("-o", "--output",    default="alerts/alerts.log", help="Alert log path")
    parser.add_argument("--no-dashboard",    action="store_true", help="Log-only mode")
    parser.add_argument("--pcap",            default=None, help="Analyse a .pcap file")
    args = parser.parse_args()

    alert_logger = AlertLogger(args.output)
    detector     = ThreatDetector(alert_logger)

    stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "alerts": 0, "uptime": "0s"}
    recent_alerts: list = []
    start_time = time.time()
#krycek
    def process_packet(packet):
        stats["total"] += 1

        alerts = detector.analyse(packet)

        elapsed = int(time.time() - start_time)
        stats["uptime"] = f"{elapsed // 3600:02d}h {(elapsed % 3600) // 60:02d}m {elapsed % 60:02d}s"
        if packet.haslayer(TCP):   stats["tcp"]  += 1
        elif packet.haslayer(UDP): stats["udp"]  += 1
        elif packet.haslayer(ICMP):stats["icmp"] += 1
        for alert in detector.analyse(packet):
            stats["alerts"] += 1
            recent_alerts.append(alert)

    if args.no_dashboard or args.pcap:
        console.print("[bold cyan]Network Packet Analyser & IDS[/] starting...\n")
        if args.pcap:
            sniff(offline=args.pcap, prn=process_packet, store=False)
            console.print(f"\n[green]Done.[/] {stats['total']} packets, {stats['alerts']} alerts.")
        else:
            try:
                sniff(iface=args.interface, prn=process_packet, store=False)
            except KeyboardInterrupt:
                console.print("\n[bold]Capture stopped.[/]")
    else:
        with Live(build_dashboard(stats, recent_alerts), refresh_per_second=2, console=console) as live:
            def update_and_process(packet):
                process_packet(packet)
                live.update(build_dashboard(stats, recent_alerts))
            try:
                if args.pcap:
                    sniff(offline=args.pcap, prn=update_and_process, store=False)
                else:
                    sniff(iface=args.interface, prn=update_and_process, store=False)
            except KeyboardInterrupt:
                pass
        console.print(f"\n[bold green]Session complete.[/] {stats['total']} packets, {stats['alerts']} alerts → [cyan]{args.output}[/].")


if __name__ == "__main__":
    main()
