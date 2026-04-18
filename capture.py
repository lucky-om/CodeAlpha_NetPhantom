"""
capture.py - Packet Capture Engine using Scapy
NetPhantom — Network Packet Sniffer Tool
Author: Lucky | Cybersecurity Portfolio Project
"""

import threading
import queue
import time
import sys
from scapy.all import sniff, wrpcap, conf

from analyzer import PacketAnalyzer


# ─────────────────────────────────────────────
#  Capture Engine
# ─────────────────────────────────────────────
class CaptureEngine:
    """
    Thread-safe packet capture engine.
    Sniffs packets on a given interface and pushes
    parsed results to a thread-safe Queue for GUI/CLI consumers.
    """

    def __init__(self, interface: str = None, bpf_filter: str = "", save_path: str = None):
        self.interface = interface or conf.iface
        self.bpf_filter = bpf_filter.strip()
        self.save_path = save_path

        self.analyzer = PacketAnalyzer()
        self.packet_queue: queue.Queue = queue.Queue(maxsize=5000)
        self.raw_packets = []           # For PCAP / JSON export

        self._stop_event = threading.Event()
        self._capture_thread: threading.Thread | None = None
        self._running = False

        self.start_time: float | None = None
        self.pps_counter = 0            # Packets this second
        self.pps_value = 0              # Exported/read packets/sec
        self._pps_last_ts: float = 0

    # ─────────────────────────────────────────
    #  Public API
    # ─────────────────────────────────────────
    def start(self):
        """Start packet capture in a background thread."""
        if self._running:
            return
        self._stop_event.clear()
        self.analyzer.reset()
        self.raw_packets.clear()
        # Drain any stale queue items
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break

        self.start_time = time.time()
        self._pps_last_ts = self.start_time
        self._running = True

        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="CaptureThread",
        )
        self._capture_thread.start()

    def stop(self):
        """Signal the capture thread to stop."""
        self._stop_event.set()
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        """Return current capture stats including packets/sec."""
        stats = self.analyzer.get_stats()
        now = time.time()
        elapsed = now - self._pps_last_ts
        if elapsed >= 1.0:
            self.pps_value = round(self.pps_counter / elapsed, 1)
            self.pps_counter = 0
            self._pps_last_ts = now
        stats["pps"] = self.pps_value
        if self.start_time:
            stats["elapsed"] = round(time.time() - self.start_time, 1)
        return stats

    # ─────────────────────────────────────────
    #  Export
    # ─────────────────────────────────────────
    def export_pcap(self, path: str) -> bool:
        """Save captured packets to a .pcap file."""
        if not self.raw_packets:
            return False
        try:
            wrpcap(path, self.raw_packets)
            return True
        except Exception as e:
            print(f"[!] PCAP export failed: {e}", file=sys.stderr)
            return False

    def export_json(self, path: str) -> bool:
        """Save parsed packet summaries to a JSON file."""
        import json
        data = []
        while not self.packet_queue.empty():
            try:
                pkt_info = self.packet_queue.get_nowait()
                # Remove non-serialisable raw_pkt
                safe = {k: v for k, v in pkt_info.items() if k != "raw_pkt"}
                data.append(safe)
            except queue.Empty:
                break
        # Also flush already-queued packets
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"[!] JSON export failed: {e}", file=sys.stderr)
            return False

    # ─────────────────────────────────────────
    #  Internal
    # ─────────────────────────────────────────
    def _capture_loop(self):
        """Run Scapy sniff() in a loop until stop is signalled."""
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter if self.bpf_filter else None,
                    prn=self._packet_callback,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                    timeout=1,          # Re-check stop_event every second
                )
            except PermissionError:
                print(
                    "\n[!] Permission denied. Run as Administrator / root.\n",
                    file=sys.stderr,
                )
                self._running = False
                break
            except OSError as e:
                # Interface may not exist or be down
                print(f"\n[!] Capture error: {e}\n", file=sys.stderr)
                self._running = False
                break

    def _packet_callback(self, pkt):
        """Called by Scapy for every captured packet."""
        try:
            self.raw_packets.append(pkt)
            pkt_info = self.analyzer.parse(pkt)
            self.pps_counter += 1

            # If a save path was set, auto-save every 100 packets
            if self.save_path and len(self.raw_packets) % 100 == 0:
                self.export_pcap(self.save_path)

            # Non-blocking put; drop if queue is full
            try:
                self.packet_queue.put_nowait(pkt_info)
            except queue.Full:
                pass  # Back-pressure: skip to avoid UI lag
        except Exception:
            pass  # Never crash the sniffer thread


# ─────────────────────────────────────────────
#  Utility: List available interfaces
# ─────────────────────────────────────────────
def list_interfaces() -> list[str]:
    """Return a list of available human-readable network interface names, prioritizing non-loopback."""
    try:
        from scapy.all import get_working_ifaces
        ifaces = [iface.name for iface in get_working_ifaces() if iface.name]
        
        # Sift loopback interfaces to the bottom
        sorted_ifaces = [i for i in ifaces if "loopback" not in i.lower() and i != "lo"]
        sorted_ifaces += [i for i in ifaces if "loopback" in i.lower() or i == "lo"]
        
        return sorted_ifaces if sorted_ifaces else [conf.iface]
    except Exception:
        # Fallback if get_working_ifaces fails
        from scapy.arch import get_if_list
        try:
            raw = get_if_list()
            sorted_raw = [i for i in raw if "lo" not in i.lower()]
            sorted_raw += [i for i in raw if "lo" in i.lower()]
            return sorted_raw
        except Exception:
            return [str(conf.iface)]
