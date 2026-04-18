"""
main.py - Entry Point / Mode Selector
NetPhantom — Network Packet Sniffer Tool
Author: Lucky | Cybersecurity Portfolio Project

Usage:
    sudo python main.py

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
            "NetPhantom v1.0 — Professional Network Packet Sniffer (Dashboard Edition)\n"
            "  Usage: sudo python main.py"
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

    # ── Launch GUI ─────────────────────────────
    try:
        from gui import run_gui
        run_gui()
    except ImportError as e:
        print(f"[!] GUI dependencies missing: {e}")
        print("    Install: pip install tk scapy")
        sys.exit(1)


if __name__ == "__main__":
    main()
