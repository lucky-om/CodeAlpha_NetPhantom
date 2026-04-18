"""
main.py - Entry Point
NetPhantom — Network Packet Sniffer & Analyzer
Author: Lucky | Cybersecurity Portfolio Project

Usage:
    sudo python3 main.py
    python main.py              (launches GUI directly)
    python main.py -l           (list interfaces)
"""

import argparse
import sys
import os


def check_privileges() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="netphantom",
        description="NetPhantom v2.0 — Professional Network Packet Sniffer\n  Usage: sudo python3 main.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", "-V", action="version", version="NetPhantom v2.0")
    parser.add_argument("--list-interfaces", "-l", action="store_true",
                        help="Print available network interfaces and exit")
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.list_interfaces:
        from capture import list_interfaces
        ifaces = list_interfaces()
        print("\nAvailable Network Interfaces:")
        for i, iface in enumerate(ifaces, 1):
            print(f"  {i}. {iface}")
        print()
        sys.exit(0)

    if not check_privileges():
        print(
            "\n[!] Not running with Administrator/root privileges.\n"
            "    Packet capture may be limited or fail.\n"
            "    → Linux: sudo python3 main.py\n"
            "    → Windows: Run as Administrator\n"
        )

    try:
        from gui import run_gui
        run_gui()
    except ImportError as e:
        print(f"[!] GUI dependency missing: {e}")
        print("    Install: pip install scapy colorama")
        sys.exit(1)


if __name__ == "__main__":
    main()
