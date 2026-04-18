"""
main.py - Entry Point / Mode Selector
NetPhantom — Network Packet Sniffer Tool
Author: Lucky | Cybersecurity Portfolio Project

Usage:
    python main.py --mode gui
    python main.py --mode cli --interface eth0 --filter tcp --save out.pcap
    python main.py --mode cli --interface wlan0 --verbose

Tool: NetPhantom
"""

import argparse
import sys
import os


def check_privileges() -> bool:
    """Return True if running with elevated privileges."""
    if os.name == "nt":                     # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:                                   # Linux / macOS
        return os.geteuid() == 0


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="netphantom",
        description=(
            "NetPhantom v1.0 — Professional Dual-Mode Network Packet Sniffer\n"
            "  GUI: python main.py --mode gui\n"
            "  CLI: python main.py --mode cli --interface eth0 --filter tcp"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version="NetPhantom v1.0",
        help="Show program's version number and exit"
    )

    parser.add_argument(
        "--mode", "-m",
        choices=["gui", "cli"],
        default="gui",
        help="Launch mode: gui (default) or cli",
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface to capture on (e.g., eth0, wlan0, Wi-Fi)",
    )
    parser.add_argument(
        "--filter", "-f",
        default="",
        dest="filter",
        help="BPF filter expression (e.g., 'tcp', 'udp port 53', 'icmp')",
    )
    parser.add_argument(
        "--save", "-s",
        default=None,
        help="Save captured packets to a .pcap file",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print full packet details in CLI mode",
    )
    parser.add_argument(
        "--list-interfaces", "-l",
        action="store_true",
        help="List available network interfaces and exit",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    # ── List interfaces and exit ───────────────
    if args.list_interfaces:
        from capture import list_interfaces
        ifaces = list_interfaces()
        print("\nAvailable Network Interfaces:")
        for i, iface in enumerate(ifaces, 1):
            print(f"  {i}. {iface}")
        print()
        sys.exit(0)

    # ── Privilege Check ────────────────────────
    if not check_privileges():
        print(
            "\n[!] WARNING: Not running with Administrator/root privileges.\n"
            "    Packet capture may be limited or fail entirely.\n"
            "    → Windows: Run as Administrator\n"
            "    → Linux/macOS: Use sudo\n"
        )

    # ── Mode Dispatch ──────────────────────────
    if args.mode == "gui":
        try:
            from gui import run_gui
            run_gui()
        except ImportError as e:
            print(f"[!] GUI dependencies missing: {e}")
            print("    Install: pip install tk scapy")
            sys.exit(1)

    elif args.mode == "cli":
        try:
            from cli import run_cli
            run_cli(args)
        except ImportError as e:
            print(f"[!] CLI dependencies missing: {e}")
            print("    Install: pip install scapy colorama")
            sys.exit(1)

    else:
        print(f"[!] Unknown mode: {args.mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
