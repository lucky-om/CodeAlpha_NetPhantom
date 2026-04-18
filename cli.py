"""
cli.py - Command-Line Interface Mode
NetPhantom — Network Packet Sniffer Tool
Author: Lucky | Cybersecurity Portfolio Project

Usage:
    python main.py --mode cli --interface eth0 --filter tcp --save capture.pcap

Tool: NetPhantom
"""

import sys
import time
import signal
import argparse
import queue

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:  # noqa: D101
        GREEN = RED = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:  # noqa: D101
        BRIGHT = DIM = RESET_ALL = ""

from capture import CaptureEngine, list_interfaces
from analyzer import format_packet_details


# ─────────────────────────────────────────────
#  Color Map
# ─────────────────────────────────────────────
PROTO_COLORS = {
    "TCP":             Fore.GREEN,
    "UDP":             Fore.BLUE,
    "ICMP":            Fore.YELLOW,
    "ARP":             Fore.MAGENTA,
    "DNS":             Fore.CYAN,
    "IPv6":            Fore.WHITE,
    "HTTP":            Fore.MAGENTA,
    "HTTPS":           Fore.CYAN,
    "TLS ClientHello": Fore.MAGENTA,
    "TLS ServerHello": Fore.MAGENTA,
    "TLS":             Fore.CYAN,
    "QUIC":            Fore.CYAN,
    "OTHER":           Fore.WHITE,
}

BANNER = r"""
{cyan}{bright}
  ███╗   ██╗███████╗████████╗    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██╔██╗ ██║█████╗     ██║       ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██║╚██╗██║██╔══╝     ██║       ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║ ╚████║███████╗   ██║       ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
{reset}
  {green}NetPhantom v1.0  |  Network Packet Sniffer  |  CLI Mode  |  Portfolio Project{reset}
""".format(
    cyan=Fore.CYAN + Style.BRIGHT,
    green=Fore.GREEN,
    bright=Style.BRIGHT,
    reset=Style.RESET_ALL if HAS_COLOR else "",
)


# ─────────────────────────────────────────────
#  CLI Main Function
# ─────────────────────────────────────────────
def run_cli(args: argparse.Namespace):
    """Entry point for CLI mode (NetPhantom)."""
    print(BANNER)

    # ── Ethics / Warning ──────────────────────
    _print_warning()

    # ── Show available interfaces if no --interface ──
    if not args.interface:
        ifaces = list_interfaces()
        print(f"{Fore.CYAN}[*] Available interfaces:{Style.RESET_ALL}")
        for i, iface in enumerate(ifaces, 1):
            print(f"    {i}. {iface}")
        print()
        args.interface = ifaces[0] if ifaces else None
        if args.interface:
            print(f"{Fore.YELLOW}[!] Defaulting to: {args.interface}{Style.RESET_ALL}\n")

    # ── Build & start engine ──────────────────
    engine = CaptureEngine(
        interface=args.interface,
        bpf_filter=args.filter or "",
        save_path=args.save or None,
    )

    # ── Graceful shutdown on Ctrl-C ───────────
    def _signal_handler(sig, frame):
        print(f"\n\n{Fore.YELLOW}[*] Stopping capture...{Style.RESET_ALL}")
        engine.stop()
        _print_final_stats(engine)
        if args.save:
            if engine.export_pcap(args.save):
                print(f"{Fore.GREEN}[+] PCAP saved → {args.save}{Style.RESET_ALL}")
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)

    print(
        f"{Fore.GREEN}[+]{Style.RESET_ALL} Sniffing on "
        f"{Fore.CYAN}{args.interface}{Style.RESET_ALL}"
        f"  filter={Fore.CYAN}'{args.filter or 'none'}'{Style.RESET_ALL}"
        f"  save={Fore.CYAN}{args.save or 'no'}{Style.RESET_ALL}\n"
    )
    _print_table_header()

    engine.start()

    # ── Main display loop ─────────────────────
    detail_pkt = None
    pkt_count = 0

    try:
        while True:
            # Drain the queue in batches
            batch = 0
            while batch < 20:
                try:
                    pkt_info = engine.packet_queue.get(timeout=0.05)
                    _print_packet_row(pkt_info, args.verbose)

                    if pkt_info.get("alert"):
                        _print_alert(pkt_info["alert"])

                    pkt_count += 1
                    batch += 1

                    # Detailed view if -v/--verbose
                    if args.verbose:
                        detail_pkt = pkt_info
                        print(f"\n{Fore.WHITE}{format_packet_details(detail_pkt)}{Style.RESET_ALL}\n")
                        _print_table_header()

                except queue.Empty:
                    break

            # Print stats every 2 seconds
            if pkt_count > 0 and pkt_count % 50 == 0:
                stats = engine.get_stats()
                _print_stats_line(stats)

            time.sleep(0.01)

    except KeyboardInterrupt:
        _signal_handler(None, None)


# ─────────────────────────────────────────────
#  Display Helpers
# ─────────────────────────────────────────────
def _print_table_header():
    header = (
        f"{Style.BRIGHT}"
        f"{'#':<6}{'Time':<14}{'Source':<20}{'Destination':<20}"
        f"{'Proto':<10}{'Behavior':<24}{'Len':>6}{'  Info':<15}"
        f"{Style.RESET_ALL}"
    )
    sep = "─" * 80
    print(f"{Fore.WHITE}{sep}")
    print(header)
    print(f"{sep}{Style.RESET_ALL}")


def _print_packet_row(pkt: dict, verbose: bool = False):
    proto = pkt["protocol"]
    color = PROTO_COLORS.get(proto, Fore.WHITE)

    src = pkt["src"]
    if pkt.get("sport"):
        src = f"{src}:{pkt['sport']}"
    dst = pkt["dst"]
    if pkt.get("dport"):
        dst = f"{dst}:{pkt['dport']}"

    proto_str = proto[:9]
    behavior_str = pkt.get("behavior", proto)[:23]
    info_str = "  "
    if pkt.get("tls_info"): info_str += str(pkt["tls_info"])[:25]
    elif pkt.get("http_info"): info_str += str(pkt["http_info"])[:25]
    elif pkt.get("payload_ascii"): info_str += str(pkt["payload_ascii"])[:25].replace(".", "")

    row = (
        f"{color}"
        f"{pkt['index']:<6}"
        f"{pkt['time']:<14}"
        f"{src[:19]:<20}"
        f"{dst[:19]:<20}"
        f"{proto_str:<10}"
        f"{behavior_str:<24}"
        f"{pkt['length']:>6}"
        f"{info_str}"
        f"{Style.RESET_ALL}"
    )
    print(row)


def _print_alert(msg: str):
    print(f"\n{Fore.RED}{Style.BRIGHT}  🚨 ALERT: {msg}{Style.RESET_ALL}\n")
    _print_table_header()


def _print_stats_line(stats: dict):
    proto_str = "  ".join(
        f"{k}:{v}" for k, v in stats.get("protocols", {}).items()
    )
    print(
        f"\n{Fore.CYAN}[STATS] "
        f"Total={stats['total']}  "
        f"PPS={stats.get('pps', 0)}  "
        f"Elapsed={stats.get('elapsed', 0)}s  "
        f"{proto_str}{Style.RESET_ALL}\n"
    )
    _print_table_header()


def _print_final_stats(engine: CaptureEngine):
    stats = engine.get_stats()
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═'*50}")
    print("  FINAL CAPTURE STATISTICS")
    print(f"{'═'*50}{Style.RESET_ALL}")
    print(f"  Total Packets  : {stats['total']}")
    print(f"  Elapsed Time   : {stats.get('elapsed', 'N/A')}s")
    print(f"  Avg PPS        : {stats.get('pps', 0)}")
    print()
    print(f"  Protocol Breakdown:")
    for proto, count in stats.get("protocols", {}).items():
        bar = "█" * min(count, 40)
        print(f"    {proto:<8} {count:>6}  {Fore.GREEN}{bar}{Style.RESET_ALL}")
    print()
    if stats.get("alerts"):
        print(f"  {Fore.RED}Alerts Triggered ({len(stats['alerts'])}):{Style.RESET_ALL}")
        for alert in stats["alerts"][-5:]:
            print(f"    • {alert}")
    print(f"{Fore.CYAN}{'═'*50}{Style.RESET_ALL}\n")


def _print_warning():
    print(
        f"{Fore.RED}{Style.BRIGHT}"
        "  ╔══════════════════════════════════════════════╗\n"
        "  ║  ⚠  ETHICAL USE WARNING                      ║\n"
        "  ║                                              ║\n"
        "  ║  This tool is for authorized use ONLY.       ║\n"
        "  ║  Capturing traffic without permission is     ║\n"
        "  ║  illegal. Use responsibly.                   ║\n"
        "  ╚══════════════════════════════════════════════╝"
        f"{Style.RESET_ALL}\n"
    )
    time.sleep(1)
