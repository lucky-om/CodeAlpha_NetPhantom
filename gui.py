"""
gui.py - Hacker-Style GUI Dashboard (Tkinter)
NetPhantom — Network Packet Sniffer Tool
Author: Lucky | Cybersecurity Portfolio Project
"""

import sys
import time
import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime

from capture import CaptureEngine, list_interfaces
from analyzer import format_packet_details


# ──────────────────────────────────────────────
#  Theme Constants
# ──────────────────────────────────────────────
BG_DARK      = "#0a0f0a"        # near-black green tinted
BG_PANEL     = "#0d150d"
BG_LIGHTER   = "#111c11"
BG_ROW_ALT   = "#0f180f"
NEON_GREEN   = "#00ff41"
NEON_CYAN    = "#00e5ff"
NEON_YELLOW  = "#ffe100"
NEON_ORANGE  = "#ff6b00"
NEON_RED     = "#ff2244"
NEON_BLUE    = "#3a9bff"
NEON_PURPLE  = "#bf5fff"
TEXT_DIM     = "#4a7a4a"
TEXT_MID     = "#7dbf7d"
FONT_MONO    = ("Courier New", 10)
FONT_MONO_SM = ("Courier New", 9)
FONT_MONO_LG = ("Courier New", 12, "bold")
FONT_HDR     = ("Courier New", 11, "bold")

PROTO_COLORS = {
    "TCP":             NEON_GREEN,
    "UDP":             NEON_BLUE,
    "ICMP":            NEON_YELLOW,
    "ARP":             NEON_PURPLE,
    "DNS":             NEON_CYAN,
    "IPv6":            TEXT_MID,
    "HTTP":            "#ff00ff",   # Magenta
    "HTTPS":           "#00ffcc",   # Teal
    "TLS ClientHello": "#ff2a75",   # Pink
    "TLS ServerHello": "#ff2a75",
    "TLS":             "#00ffcc",
    "QUIC":            "#00ffcc",
    "OTHER":           TEXT_DIM,
}


# ──────────────────────────────────────────────
#  Main GUI Application
# ──────────────────────────────────────────────
class PacketSnifferGUI:
    MAX_TABLE_ROWS = 2000

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NetPhantom v1.0  |  Network Packet Sniffer  |  by Lucky")
        self.root.configure(bg=BG_DARK)
        self.root.geometry("1400x860")
        self.root.minsize(1100, 700)

        self.engine: CaptureEngine | None = None
        self._poll_job = None
        self._stored_packets: list[dict] = []       # All packets (for search)
        self._filtered_packets: list[dict] = []     # Currently displayed
        self._selected_pkt: dict | None = None
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", self._on_search_change)
        self._filter_proto_var = tk.StringVar(value="ALL")

        self._build_ui()
        self._bind_shortcuts()
        self._show_warning()

    # ────────────────────────────────────────────
    #  UI Construction
    # ────────────────────────────────────────────
    def _build_ui(self):
        self._build_title_bar()
        main_frame = tk.Frame(self.root, bg=BG_DARK)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))

        # ── Left Column: Table + Details ──────
        left = tk.Frame(main_frame, bg=BG_DARK)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._build_control_bar(left)
        self._build_packet_table(left)
        self._build_details_panel(left)

        # ── Right Column: Stats + Alerts ──────
        right = tk.Frame(main_frame, bg=BG_DARK, width=320)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(6, 0))
        right.pack_propagate(False)
        self._build_stats_panel(right)
        self._build_alerts_panel(right)

        self._build_status_bar()

    # ── Title Bar ─────────────────────────────
    def _build_title_bar(self):
        bar = tk.Frame(self.root, bg="#061006", height=44)
        bar.pack(fill=tk.X, side=tk.TOP)
        bar.pack_propagate(False)
        tk.Label(
            bar,
            text=" ⬡ NetPhantom v1.0 — Network Packet Sniffer Dashboard",
            bg="#061006", fg=NEON_GREEN,
            font=("Courier New", 13, "bold"),
            anchor="w",
        ).pack(side=tk.LEFT, padx=14, pady=8)
        tk.Label(
            bar, text="[ F5 ] Start   [ F6 ] Stop   [ Ctrl+E ] Export   [ Ctrl+F ] Search",
            bg="#061006", fg=TEXT_DIM,
            font=("Courier New", 9),
        ).pack(side=tk.RIGHT, padx=14)

    # ── Control Bar ───────────────────────────
    def _build_control_bar(self, parent):
        bar = tk.Frame(parent, bg=BG_PANEL, relief="flat")
        bar.pack(fill=tk.X, pady=(6, 4))

        # Interface
        tk.Label(bar, text="INTERFACE:", bg=BG_PANEL, fg=TEXT_MID, font=FONT_MONO_SM).pack(
            side=tk.LEFT, padx=(10, 2), pady=6)
        self._iface_var = tk.StringVar()
        ifaces = list_interfaces()
        self._iface_combo = ttk.Combobox(
            bar, textvariable=self._iface_var,
            values=ifaces, width=20, font=FONT_MONO_SM,
        )
        self._iface_combo.pack(side=tk.LEFT, padx=(0, 12))
        if ifaces:
            self._iface_combo.set(ifaces[0])

        # BPF Filter
        tk.Label(bar, text="FILTER (BPF):", bg=BG_PANEL, fg=TEXT_MID, font=FONT_MONO_SM).pack(
            side=tk.LEFT, padx=(0, 2))
        self._filter_entry = tk.Entry(
            bar, width=18, bg=BG_LIGHTER, fg=NEON_GREEN,
            insertbackground=NEON_GREEN, font=FONT_MONO_SM,
            relief="flat", bd=4,
        )
        self._filter_entry.pack(side=tk.LEFT, padx=(0, 12))

        # Buttons
        self._btn_start = self._make_btn(bar, "▶  START", NEON_GREEN,  self.start_capture)
        self._btn_stop  = self._make_btn(bar, "■  STOP",  NEON_RED,    self.stop_capture)
        self._btn_clear = self._make_btn(bar, "⟳  CLEAR", NEON_YELLOW, self.clear_packets)
        self._make_btn(bar, "⬇  EXPORT", NEON_CYAN, self._export_dialog)
        self._btn_stop.config(state=tk.DISABLED)

        # Search
        tk.Label(bar, text="SEARCH:", bg=BG_PANEL, fg=TEXT_MID, font=FONT_MONO_SM).pack(
            side=tk.LEFT, padx=(14, 2))
        self._search_entry = tk.Entry(
            bar, textvariable=self._search_var, width=16,
            bg=BG_LIGHTER, fg=NEON_CYAN,
            insertbackground=NEON_CYAN, font=FONT_MONO_SM,
            relief="flat", bd=4,
        )
        self._search_entry.pack(side=tk.LEFT, padx=(0, 6))
        self._search_entry.bind("<FocusIn>",
            lambda e: self._search_entry.config(highlightthickness=1,
                                                 highlightcolor=NEON_CYAN,
                                                 highlightbackground=NEON_CYAN))

        # Protocol filter dropdown
        proto_options = ["ALL", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "TLS", "QUIC", "IPv6"]
        tk.Label(bar, text="PROTO:", bg=BG_PANEL, fg=TEXT_MID, font=FONT_MONO_SM).pack(
            side=tk.LEFT, padx=(6, 2))
        self._proto_combo = ttk.Combobox(
            bar, textvariable=self._filter_proto_var,
            values=proto_options, width=8, font=FONT_MONO_SM, state="readonly",
        )
        self._proto_combo.pack(side=tk.LEFT, padx=(0, 6))
        self._proto_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())

    # ── Packet Table ──────────────────────────
    def _build_packet_table(self, parent):
        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        columns = ("#", "Time", "Source", "Destination", "Protocol", "Behavior", "Length", "Info")
        self._tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        self._style_treeview()

        col_widths = {"#": 50, "Time": 105, "Source": 160, "Destination": 160,
                      "Protocol": 70, "Behavior": 150, "Length": 60, "Info": 240}
        for col in columns:
            self._tree.heading(col, text=col,
                               command=lambda c=col: self._sort_by_column(c))
            self._tree.column(col, width=col_widths[col], anchor="w" if col not in ("#", "Length") else "e")

        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)
        self._tree.bind("<Double-1>", self._on_row_double_click)

    def _style_treeview(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=BG_PANEL, foreground=NEON_GREEN,
            fieldbackground=BG_PANEL,
            rowheight=22, font=FONT_MONO_SM,
        )
        style.configure(
            "Treeview.Heading",
            background=BG_LIGHTER, foreground=NEON_CYAN,
            font=("Courier New", 9, "bold"),
        )
        style.map("Treeview",
                  background=[("selected", "#1a3d1a")],
                  foreground=[("selected", NEON_GREEN)])
        style.configure("Vertical.TScrollbar",   background=BG_LIGHTER, troughcolor=BG_DARK)
        style.configure("Horizontal.TScrollbar", background=BG_LIGHTER, troughcolor=BG_DARK)
        style.configure("TCombobox", fieldbackground=BG_LIGHTER, background=BG_LIGHTER,
                        foreground=NEON_GREEN, selectbackground=BG_LIGHTER)

        # Tag colors per protocol
        for proto, color in PROTO_COLORS.items():
            self._tree.tag_configure(proto, foreground=color)
        self._tree.tag_configure("ALERT", foreground=NEON_RED)

    # ── Details Panel ─────────────────────────
    def _build_details_panel(self, parent):
        frame = self._make_section(parent, "  ▸ PACKET DETAILS", height=200)
        self._detail_text = scrolledtext.ScrolledText(
            frame, bg=BG_PANEL, fg=TEXT_MID,
            font=FONT_MONO_SM, relief="flat",
            insertbackground=NEON_GREEN,
            state=tk.DISABLED, height=10,
        )
        self._detail_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # ── Stats Panel ───────────────────────────
    def _build_stats_panel(self, parent):
        frame = self._make_section(parent, "  ▸ LIVE STATISTICS")
        stats_inner = tk.Frame(frame, bg=BG_PANEL)
        stats_inner.pack(fill=tk.X, padx=6, pady=6)

        # Counters grid
        self._stat_labels: dict[str, tk.Label] = {}
        counters = [
            ("TOTAL PKTS",  "0",   NEON_GREEN),
            ("PACKETS/SEC", "0",   NEON_CYAN),
            ("ELAPSED",     "0s",  TEXT_MID),
            ("ENCRYPTED",   "0",   "#00ffcc"),
            ("HTTP/S",      "0",   "#ff00ff"),
            ("TCP",         "0",   NEON_GREEN),
            ("UDP",         "0",   NEON_BLUE),
            ("ICMP",        "0",   NEON_YELLOW),
            ("DNS",         "0",   NEON_CYAN),
            ("OTHER",       "0",   TEXT_DIM),
        ]
        for i, (label, val, color) in enumerate(counters):
            row, col = divmod(i, 2)
            tk.Label(stats_inner, text=label+":", bg=BG_PANEL, fg=TEXT_DIM,
                     font=("Courier New", 8)).grid(row=row*2,   column=col, sticky="w", padx=6)
            lbl = tk.Label(stats_inner, text=val, bg=BG_PANEL, fg=color,
                           font=("Courier New", 14, "bold"))
            lbl.grid(row=row*2+1, column=col, sticky="w", padx=6, pady=(0, 8))
            self._stat_labels[label] = lbl

        # Protocol bar chart
        tk.Label(frame, text="  PROTOCOL DISTRIBUTION", bg=BG_PANEL,
                 fg=TEXT_DIM, font=("Courier New", 8)).pack(anchor="w", padx=6)
        self._bar_canvas = tk.Canvas(frame, bg=BG_PANEL, height=120,
                                     highlightthickness=0)
        self._bar_canvas.pack(fill=tk.X, padx=6, pady=(2, 6))

    # ── Alerts Panel ──────────────────────────
    def _build_alerts_panel(self, parent):
        frame = self._make_section(parent, "  ▸ THREAT ALERTS 🚨")
        self._alert_text = scrolledtext.ScrolledText(
            frame, bg="#1a0000", fg=NEON_RED,
            font=("Courier New", 9), relief="flat",
            state=tk.DISABLED,
        )
        self._alert_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # ── Status Bar ────────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg="#061006", height=24)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        self._status_var = tk.StringVar(value="  ● IDLE  |  Ready to capture")
        tk.Label(bar, textvariable=self._status_var,
                 bg="#061006", fg=TEXT_MID,
                 font=("Courier New", 9), anchor="w").pack(side=tk.LEFT, padx=8)
        self._clock_lbl = tk.Label(bar, text="", bg="#061006",
                                   fg=TEXT_DIM, font=("Courier New", 9))
        self._clock_lbl.pack(side=tk.RIGHT, padx=8)
        self._update_clock()

    # ────────────────────────────────────────────
    #  Capture Control
    # ────────────────────────────────────────────
    def start_capture(self):
        iface = self._iface_var.get().strip()
        bpf   = self._filter_entry.get().strip()
        if not iface:
            messagebox.showerror("No Interface", "Please select a network interface.")
            return

        self.engine = CaptureEngine(interface=iface, bpf_filter=bpf)
        self.engine.start()

        self._btn_start.config(state=tk.DISABLED)
        self._btn_stop.config(state=tk.NORMAL)
        self._set_status(f"  ● CAPTURING  |  {iface}  |  filter: '{bpf or 'none'}'", NEON_GREEN)
        self._poll_packets()

    def stop_capture(self):
        if self.engine:
            self.engine.stop()
        if self._poll_job:
            self.root.after_cancel(self._poll_job)
            self._poll_job = None
        self._btn_start.config(state=tk.NORMAL)
        self._btn_stop.config(state=tk.DISABLED)
        self._set_status("  ■ STOPPED  |  Capture halted", NEON_RED)

    def clear_packets(self):
        self._stored_packets.clear()
        self._filtered_packets.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._set_detail("")
        self._clear_alerts()
        if self.engine:
            self.engine.analyzer.reset()

    # ────────────────────────────────────────────
    #  Packet Polling Loop
    # ────────────────────────────────────────────
    def _poll_packets(self):
        if not self.engine:
            return
        try:
            batch = 0
            while batch < 30:
                try:
                    pkt_info = self.engine.packet_queue.get_nowait()
                    self._stored_packets.append(pkt_info)
                    self._add_table_row(pkt_info)
                    if pkt_info.get("alert"):
                        self._add_alert(pkt_info["alert"])
                    batch += 1
                except queue.Empty:
                    break

            # Update stats every poll
            if self.engine and self.engine.is_running():
                self._update_stats(self.engine.get_stats())

        except Exception as e:
            print(f"[GUI] poll error: {e}")

        finally:
            self._poll_job = self.root.after(80, self._poll_packets)

    # ────────────────────────────────────────────
    #  Table Management
    # ────────────────────────────────────────────
    def _add_table_row(self, pkt: dict):
        # Apply search/proto filter
        if not self._matches_filter(pkt):
            return

        proto = pkt["protocol"]
        src = pkt["src"] + (f":{pkt['sport']}" if pkt.get("sport") else "")
        dst = pkt["dst"] + (f":{pkt['dport']}" if pkt.get("dport") else "")
        
        info = ""
        if pkt.get("tls_info"):
            info = pkt["tls_info"]
        elif pkt.get("http_info"):
            info = pkt["http_info"]
        else:
            info = pkt.get("flags") or pkt.get("payload_ascii", "")[:40].replace(".", "") or pkt.get("summary", "")[:40]

        tag = proto if not pkt.get("alert") else "ALERT"
        iid = self._tree.insert(
            "", "end",
            values=(pkt["index"], pkt["time"], src[:24], dst[:24], proto, pkt.get("behavior", proto), pkt["length"], info),
            tags=(tag,),
        )
        # Store pkt_info in a dict keyed by iid
        self._tree.item_to_pkt = getattr(self._tree, "item_to_pkt", {})
        self._tree.item_to_pkt[iid] = pkt

        # Prune old rows if over limit
        children = self._tree.get_children()
        if len(children) > self.MAX_TABLE_ROWS:
            self._tree.delete(children[0])

        # Auto-scroll to bottom
        self._tree.yview_moveto(1.0)

    # ────────────────────────────────────────────
    #  Stats Panel Update
    # ────────────────────────────────────────────
    def _update_stats(self, stats: dict):
        self._stat_labels["TOTAL PKTS"].config(text=str(stats["total"]))
        self._stat_labels["PACKETS/SEC"].config(text=str(stats.get("pps", 0)))
        self._stat_labels["ELAPSED"].config(text=f"{stats.get('elapsed', 0)}s")

        protos = stats.get("protocols", {})
        enc_count = 0
        http_count = 0
        for p, c in protos.items():
            if "TLS" in p or "HTTPS" in p or "QUIC" in p: enc_count += c
            if "HTTP" in p: http_count += c

        if "ENCRYPTED" in self._stat_labels:
            self._stat_labels["ENCRYPTED"].config(text=str(enc_count))
        if "HTTP/S" in self._stat_labels:
            self._stat_labels["HTTP/S"].config(text=str(http_count))

        for proto in ("TCP", "UDP", "ICMP", "DNS", "OTHER"):
            if proto in self._stat_labels:
                self._stat_labels[proto].config(text=str(protos.get(proto, 0)))

        self._draw_bar_chart(protos, stats["total"])

    def _draw_bar_chart(self, protos: dict, total: int):
        canvas = self._bar_canvas
        canvas.delete("all")
        if total == 0:
            return

        w = canvas.winfo_width() or 280
        bar_w = max(8, (w - 20) // max(len(protos), 1) - 6)
        x = 10
        max_h = 80

        sorted_protos = sorted(protos.items(), key=lambda kv: kv[1], reverse=True)
        for proto, count in sorted_protos:
            pct = count / total
            bar_h = max(2, int(pct * max_h))
            color = PROTO_COLORS.get(proto, TEXT_DIM)
            y0, y1 = 100, 100 - bar_h
            canvas.create_rectangle(x, y0, x + bar_w, y1, fill=color, outline="")
            canvas.create_text(x + bar_w // 2, 108, text=proto[:3],
                               fill=color, font=("Courier New", 7))
            canvas.create_text(x + bar_w // 2, y1 - 8, text=str(count),
                               fill=color, font=("Courier New", 7))
            x += bar_w + 6

    # ────────────────────────────────────────────
    #  Alerts
    # ────────────────────────────────────────────
    def _add_alert(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._alert_text.config(state=tk.NORMAL)
        self._alert_text.insert(tk.END, f"[{ts}] {msg}\n")
        self._alert_text.see(tk.END)
        self._alert_text.config(state=tk.DISABLED)

    def _clear_alerts(self):
        self._alert_text.config(state=tk.NORMAL)
        self._alert_text.delete("1.0", tk.END)
        self._alert_text.config(state=tk.DISABLED)

    # ────────────────────────────────────────────
    #  Row Selection / Details
    # ────────────────────────────────────────────
    def _on_row_select(self, event):
        sel = self._tree.selection()
        if not sel:
            return
        iid = sel[0]
        item_to_pkt = getattr(self._tree, "item_to_pkt", {})
        pkt = item_to_pkt.get(iid)
        if pkt:
            self._selected_pkt = pkt
            self._set_detail(format_packet_details(pkt))

    def _on_row_double_click(self, event):
        """Open full detail in a popup window."""
        if not self._selected_pkt:
            return
        popup = tk.Toplevel(self.root)
        popup.title(f"Packet #{self._selected_pkt['index']} Details")
        popup.configure(bg=BG_DARK)
        popup.geometry("700x500")
        txt = scrolledtext.ScrolledText(
            popup, bg=BG_PANEL, fg=NEON_GREEN,
            font=FONT_MONO_SM, relief="flat",
        )
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        txt.insert(tk.END, format_packet_details(self._selected_pkt))
        txt.config(state=tk.DISABLED)

    def _set_detail(self, text: str):
        self._detail_text.config(state=tk.NORMAL)
        self._detail_text.delete("1.0", tk.END)
        self._detail_text.insert(tk.END, text)
        self._detail_text.config(state=tk.DISABLED)

    # ────────────────────────────────────────────
    #  Search & Filter
    # ────────────────────────────────────────────
    def _on_search_change(self, *_):
        self._apply_filter()

    def _apply_filter(self):
        """Re-draw the table based on search text and proto filter."""
        # Clear table without clearing stored packets
        for item in self._tree.get_children():
            self._tree.delete(item)
        item_to_pkt = {}
        self._tree.item_to_pkt = item_to_pkt

        for pkt in self._stored_packets:
            if self._matches_filter(pkt):
                proto = pkt["protocol"]
                src = pkt["src"] + (f":{pkt['sport']}" if pkt.get("sport") else "")
                dst = pkt["dst"] + (f":{pkt['dport']}" if pkt.get("dport") else "")
                
                info = ""
                if pkt.get("tls_info"):
                    info = pkt["tls_info"]
                elif pkt.get("http_info"):
                    info = pkt["http_info"]
                else:
                    info = pkt.get("flags") or pkt.get("payload_ascii", "")[:40].replace(".", "") or ""
                    
                tag = proto if not pkt.get("alert") else "ALERT"
                iid = self._tree.insert(
                    "", "end",
                    values=(pkt["index"], pkt["time"], src[:24], dst[:24], proto, pkt.get("behavior", proto), pkt["length"], info),
                    tags=(tag,),
                )
                item_to_pkt[iid] = pkt

    def _matches_filter(self, pkt: dict) -> bool:
        query = self._search_var.get().lower().strip()
        proto_filter = self._filter_proto_var.get()

        if proto_filter != "ALL" and pkt["protocol"] != proto_filter:
            return False

        if query:
            haystack = f"{pkt['src']} {pkt['dst']} {pkt['protocol']} {pkt.get('payload', '')}".lower()
            if query not in haystack:
                return False
        return True

    # ────────────────────────────────────────────
    #  Column Sorting
    # ────────────────────────────────────────────
    def _sort_by_column(self, col: str):
        data = [(self._tree.set(iid, col), iid) for iid in self._tree.get_children()]
        try:
            data.sort(key=lambda t: float(t[0]))
        except ValueError:
            data.sort(key=lambda t: t[0].lower())
        for idx, (_, iid) in enumerate(data):
            self._tree.move(iid, "", idx)

    # ────────────────────────────────────────────
    #  Export Dialog
    # ────────────────────────────────────────────
    def _export_dialog(self):
        if not self.engine:
            messagebox.showinfo("No Data", "Start a capture first.")
            return

        popup = tk.Toplevel(self.root)
        popup.title("Export Packets")
        popup.configure(bg=BG_DARK)
        popup.geometry("360x180")
        popup.resizable(False, False)

        tk.Label(popup, text="Export Format", bg=BG_DARK, fg=NEON_GREEN,
                 font=FONT_HDR).pack(pady=(20, 8))

        btn_frame = tk.Frame(popup, bg=BG_DARK)
        btn_frame.pack()

        def export_pcap():
            path = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All", "*.*")],
                title="Save PCAP",
            )
            if path:
                ok = self.engine.export_pcap(path)
                popup.destroy()
                messagebox.showinfo("Done", f"{'Saved' if ok else 'Failed'}: {path}")

        def export_json():
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All", "*.*")],
                title="Save JSON",
            )
            if path:
                import json
                data = [
                    {k: v for k, v in p.items() if k != "raw_pkt"}
                    for p in self._stored_packets
                ]
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)
                popup.destroy()
                messagebox.showinfo("Done", f"Saved {len(data)} packets → {path}")

        self._make_btn(btn_frame, "💾  Save PCAP", NEON_GREEN,  export_pcap).pack(side=tk.LEFT, padx=10)
        self._make_btn(btn_frame, "📋  Save JSON", NEON_CYAN,   export_json).pack(side=tk.LEFT, padx=10)
        self._make_btn(btn_frame, "✕  Cancel",    NEON_YELLOW, popup.destroy).pack(side=tk.LEFT, padx=10)

    # ────────────────────────────────────────────
    #  Keyboard Shortcuts
    # ────────────────────────────────────────────
    def _bind_shortcuts(self):
        self.root.bind("<F5>",        lambda e: self.start_capture())
        self.root.bind("<F6>",        lambda e: self.stop_capture())
        self.root.bind("<Control-e>", lambda e: self._export_dialog())
        self.root.bind("<Control-f>", lambda e: self._search_entry.focus_set())
        self.root.bind("<Control-l>", lambda e: self.clear_packets())
        self.root.bind("<Escape>",    lambda e: self.stop_capture())

    # ────────────────────────────────────────────
    #  Helpers
    # ────────────────────────────────────────────
    def _make_section(self, parent, title: str, height: int = None) -> tk.Frame:
        outer = tk.Frame(parent, bg=BG_PANEL, bd=0, relief="flat")
        if height:
            outer.pack(fill=tk.X, pady=2)
            outer.config(height=height)
            outer.pack_propagate(False)
        else:
            outer.pack(fill=tk.BOTH, expand=True, pady=2)
        tk.Label(outer, text=title, bg=BG_PANEL, fg=NEON_CYAN,
                 font=("Courier New", 9, "bold")).pack(anchor="w", padx=4, pady=(4, 0))
        tk.Frame(outer, bg=TEXT_DIM, height=1).pack(fill=tk.X, padx=4)
        return outer

    def _make_btn(self, parent, text: str, color: str, cmd) -> tk.Button:
        btn = tk.Button(
            parent, text=text, command=cmd,
            bg=BG_LIGHTER, fg=color,
            activebackground="#1a2a1a", activeforeground=color,
            font=("Courier New", 9, "bold"),
            relief="flat", bd=0, padx=10, pady=4,
            cursor="hand2",
        )
        btn.pack(side=tk.LEFT, padx=4, pady=6)

        def on_enter(e, b=btn, c=color):
            b.config(bg=BG_PANEL)
        def on_leave(e, b=btn):
            b.config(bg=BG_LIGHTER)

        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    def _set_status(self, msg: str, color: str = TEXT_MID):
        self._status_var.set(msg)

    def _update_clock(self):
        self._clock_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._update_clock)

    def _show_warning(self):
        msg = (
            "⚠  ETHICAL USE WARNING\n\n"
            "This tool is intended for AUTHORIZED use ONLY.\n"
            "Capturing network traffic without explicit permission\n"
            "is illegal and unethical.\n\n"
            "By proceeding, you confirm that you have permission\n"
            "to monitor the target network.\n\n"
            "Run as Administrator/root for full capture capability."
        )
        messagebox.showwarning("NetPhantom — Ethical Use Warning", msg)

    def on_close(self):
        self.stop_capture()
        self.root.destroy()


# ──────────────────────────────────────────────
#  Launch GUI
# ──────────────────────────────────────────────
def run_gui():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
