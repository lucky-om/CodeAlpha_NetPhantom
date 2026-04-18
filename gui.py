"""
gui.py - Professional Hacker-Style GUI Dashboard
NetPhantom — Network Packet Sniffer & Analyzer
Author: Lucky | Cybersecurity Portfolio Project
"""

import sys
import time
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime

from capture import CaptureEngine, list_interfaces
from analyzer import format_packet_details

# ──────────────────────────────────────────────
#  Theme Constants
# ──────────────────────────────────────────────
BG_DARK     = "#09110e"
BG_PANEL    = "#0d1a14"
BG_LIGHTER  = "#122018"
BG_HEADER   = "#050e09"
NEON_GREEN  = "#00ff6a"
NEON_CYAN   = "#00e5ff"
NEON_YELLOW = "#ffe156"
NEON_ORANGE = "#ff8c00"
NEON_RED    = "#ff2244"
NEON_BLUE   = "#4da6ff"
NEON_PURPLE = "#c77dff"
NEON_PINK   = "#ff2a75"
TEXT_DIM    = "#3b6b52"
TEXT_MID    = "#6bbf8e"
ACCENT_LINE = "#1a3a28"

FONT_MONO    = ("Courier New", 10)
FONT_MONO_SM = ("Courier New", 9)
FONT_MONO_LG = ("Courier New", 13, "bold")
FONT_HDR     = ("Courier New", 11, "bold")
FONT_TITLE   = ("Courier New", 15, "bold")

PROTO_COLORS = {
    "TCP":             NEON_GREEN,
    "UDP":             NEON_BLUE,
    "ICMP":            NEON_YELLOW,
    "ARP":             NEON_PURPLE,
    "DNS":             NEON_YELLOW,
    "IPv6":            TEXT_MID,
    "HTTP":            NEON_ORANGE,
    "HTTPS":           NEON_CYAN,
    "TLS":             NEON_CYAN,
    "TLS ClientHello": NEON_PINK,
    "TLS ServerHello": NEON_PINK,
    "QUIC":            NEON_CYAN,
    "OTHER":           TEXT_DIM,
}


# ──────────────────────────────────────────────
#  Splash Screen
# ──────────────────────────────────────────────
def show_splash():
    splash = tk.Tk()
    splash.overrideredirect(True)
    splash.configure(bg=BG_DARK)
    w, h = 540, 300
    sw, sh = splash.winfo_screenwidth(), splash.winfo_screenheight()
    splash.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    # Border frame
    border = tk.Frame(splash, bg=NEON_GREEN, bd=2)
    border.place(relx=0, rely=0, relwidth=1, relheight=1)
    inner = tk.Frame(border, bg=BG_DARK)
    inner.place(relx=0.005, rely=0.008, relwidth=0.99, relheight=0.984)

    logo_text = (
        " _   _      _   ___ _           _\n"
        "| \\ | | ___| |_|  _ \\ |__   __ _| |\n"
        "|  \\| |/ _ \\ __| |_) | '_ \\ / _` | |\n"
        "| |\\  |  __/ |_|  __/| | | | (_| | |\n"
        "|_| \\_|\\___|\\__|_|   |_| |_|\\__,_|_|\n"
    )
    tk.Label(inner, text=logo_text, bg=BG_DARK, fg=NEON_GREEN,
             font=("Courier New", 11, "bold"), justify="left").pack(pady=(24, 4))

    tk.Label(inner, text="Network Packet Sniffer & Analyzer  v2.0",
             bg=BG_DARK, fg=NEON_CYAN,
             font=("Courier New", 10)).pack()

    tk.Label(inner, text="Author: Lucky  |  Cybersecurity Portfolio",
             bg=BG_DARK, fg=TEXT_MID,
             font=("Courier New", 9)).pack(pady=(4, 0))

    prog_frame = tk.Frame(inner, bg=BG_DARK)
    prog_frame.pack(pady=(18, 4))
    tk.Label(prog_frame, text="Initializing capture engine...",
             bg=BG_DARK, fg=TEXT_DIM, font=("Courier New", 8)).pack()
    bar = ttk.Progressbar(prog_frame, length=320, mode="determinate")
    bar.pack(pady=6)

    def advance(val=0):
        bar["value"] = val
        if val < 100:
            splash.after(18, advance, val + 5)
        else:
            splash.after(300, splash.destroy)

    splash.after(100, advance)
    splash.mainloop()


# ──────────────────────────────────────────────
#  Main GUI Application
# ──────────────────────────────────────────────
class PacketSnifferGUI:
    MAX_TABLE_ROWS = 3000

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NetPhantom v2.0  |  Network Packet Sniffer")
        self.root.configure(bg=BG_DARK)
        self.root.geometry("1440x880")
        self.root.minsize(1100, 700)

        self.engine: CaptureEngine | None = None
        self._poll_job  = None
        self._stored_packets: list[dict] = []
        self._selected_pkt: dict | None  = None
        self._search_var      = tk.StringVar()
        self._filter_proto_var = tk.StringVar(value="ALL")
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        self._auto_scroll = True

        self._build_ui()
        self._bind_shortcuts()
        self.root.after(150, self._show_warning)

    # ────────────────────────────────────────────
    #  UI Construction
    # ────────────────────────────────────────────
    def _build_ui(self):
        self._build_title_bar()
        pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=BG_DARK,
                              sashwidth=4, sashrelief="flat", sashpad=0)
        pane.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        # ── Left: Toolbar + Table + Details ──────
        left = tk.Frame(pane, bg=BG_DARK)
        pane.add(left, minsize=820, stretch="always")

        self._build_control_bar(left)
        self._build_packet_table(left)
        self._build_details_panel(left)

        # ── Right: Stats + Streams ────────────────
        right = tk.Frame(pane, bg=BG_DARK)
        pane.add(right, minsize=270, stretch="never")

        self._build_stats_panel(right)
        self._build_streams_panel(right)

        self._build_status_bar()

    # ── Title Bar ─────────────────────────────
    def _build_title_bar(self):
        bar = tk.Frame(self.root, bg=BG_HEADER, height=46)
        bar.pack(fill=tk.X, side=tk.TOP)
        bar.pack_propagate(False)

        # Logo mark
        tk.Label(bar, text="⬡", bg=BG_HEADER, fg=NEON_GREEN,
                 font=("Courier New", 20)).pack(side=tk.LEFT, padx=(10, 4), pady=6)
        tk.Label(bar, text="NetPhantom", bg=BG_HEADER, fg=NEON_GREEN,
                 font=FONT_TITLE).pack(side=tk.LEFT, pady=8)
        tk.Label(bar, text=" v2.0  — Network Packet Sniffer & Analyzer",
                 bg=BG_HEADER, fg=TEXT_MID,
                 font=("Courier New", 10)).pack(side=tk.LEFT, pady=8)

        # Right hints
        tk.Button(bar, text="ⓘ  About", command=self._show_about,
                  bg=BG_LIGHTER, fg=NEON_CYAN, relief="flat",
                  font=("Courier New", 9), padx=8, pady=4,
                  cursor="hand2", activebackground=BG_PANEL,
                  activeforeground=NEON_CYAN).pack(side=tk.RIGHT, padx=(0, 12), pady=8)
        tk.Label(bar,
                 text="F5 Start  F6 Stop  Ctrl+E Export  Ctrl+F Search",
                 bg=BG_HEADER, fg=TEXT_DIM,
                 font=("Courier New", 8)).pack(side=tk.RIGHT, padx=18)

    # ── Control Bar ───────────────────────────
    def _build_control_bar(self, parent):
        bar = tk.Frame(parent, bg=BG_PANEL, relief="flat")
        bar.pack(fill=tk.X, pady=(4, 3))

        def sep():
            tk.Frame(bar, bg=ACCENT_LINE, width=1).pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=6)

        # Interface
        tk.Label(bar, text="INTERFACE:", bg=BG_PANEL, fg=TEXT_MID,
                 font=FONT_MONO_SM).pack(side=tk.LEFT, padx=(10, 2), pady=6)
        self._iface_var   = tk.StringVar()
        ifaces = list_interfaces()
        self._iface_combo = ttk.Combobox(bar, textvariable=self._iface_var,
                                          values=ifaces, width=18, font=FONT_MONO_SM)
        self._iface_combo.pack(side=tk.LEFT, padx=(0, 4))
        if ifaces:
            self._iface_combo.set(ifaces[0])

        sep()

        # BPF Filter
        tk.Label(bar, text="BPF FILTER:", bg=BG_PANEL, fg=TEXT_MID,
                 font=FONT_MONO_SM).pack(side=tk.LEFT, padx=(0, 2))
        self._filter_entry = tk.Entry(bar, width=16, bg=BG_LIGHTER, fg=NEON_GREEN,
                                       insertbackground=NEON_GREEN, font=FONT_MONO_SM,
                                       relief="flat", bd=4)
        self._filter_entry.pack(side=tk.LEFT, padx=(0, 4))

        sep()

        # Action buttons
        self._btn_start = self._make_btn(bar, "▶ START",  NEON_GREEN,  self.start_capture)
        self._btn_stop  = self._make_btn(bar, "■ STOP",   NEON_RED,    self.stop_capture)
        self._btn_clear = self._make_btn(bar, "⟳ CLEAR",  NEON_YELLOW, self.clear_packets)
        self._make_btn(bar, "⬇ EXPORT", NEON_CYAN,   self._export_dialog)
        self._btn_stop.config(state=tk.DISABLED)

        sep()

        # Search
        tk.Label(bar, text="SEARCH:", bg=BG_PANEL, fg=TEXT_MID,
                 font=FONT_MONO_SM).pack(side=tk.LEFT, padx=(0, 2))
        self._search_entry = tk.Entry(bar, textvariable=self._search_var, width=15,
                                       bg=BG_LIGHTER, fg=NEON_CYAN,
                                       insertbackground=NEON_CYAN, font=FONT_MONO_SM,
                                       relief="flat", bd=4)
        self._search_entry.pack(side=tk.LEFT, padx=(0, 4))

        sep()

        # Proto filter
        tk.Label(bar, text="PROTO:", bg=BG_PANEL, fg=TEXT_MID,
                 font=FONT_MONO_SM).pack(side=tk.LEFT, padx=(0, 2))
        self._proto_combo = ttk.Combobox(
            bar, textvariable=self._filter_proto_var, state="readonly",
            values=["ALL","TCP","UDP","ICMP","ARP","DNS","HTTP","HTTPS","TLS","QUIC","IPv6"],
            width=8, font=FONT_MONO_SM)
        self._proto_combo.pack(side=tk.LEFT, padx=(0, 4))
        self._proto_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())

        # Auto-scroll toggle
        sep()
        self._auto_scroll_var = tk.BooleanVar(value=True)
        tk.Checkbutton(bar, text="Auto-scroll", variable=self._auto_scroll_var,
                       bg=BG_PANEL, fg=TEXT_MID, selectcolor=BG_LIGHTER,
                       activebackground=BG_PANEL, font=FONT_MONO_SM,
                       command=lambda: setattr(self, "_auto_scroll", self._auto_scroll_var.get())
                       ).pack(side=tk.LEFT, padx=4)

    # ── Packet Table ──────────────────────────
    def _build_packet_table(self, parent):
        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 3))

        columns = ("#", "Time", "Source", "Destination", "Protocol", "Behavior", "Length", "Info")
        self._tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        self._style_treeview()

        col_widths = {"#": 48, "Time": 100, "Source": 155, "Destination": 155,
                      "Protocol": 68, "Behavior": 148, "Length": 58, "Info": 240}
        for col in columns:
            anchor = "e" if col in ("#", "Length") else "w"
            self._tree.heading(col, text=col, command=lambda c=col: self._sort_by_column(c))
            self._tree.column(col, width=col_widths[col], anchor=anchor, minwidth=30)

        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)
        self._tree.bind("<Double-1>",         self._on_row_double_click)
        self._item_pkt: dict[str, dict] = {}

    def _style_treeview(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background=BG_PANEL, foreground=NEON_GREEN,
                        fieldbackground=BG_PANEL, rowheight=22, font=FONT_MONO_SM)
        style.configure("Treeview.Heading",
                        background=BG_LIGHTER, foreground=NEON_CYAN,
                        font=("Courier New", 9, "bold"))
        style.map("Treeview",
                  background=[("selected", "#12352a")],
                  foreground=[("selected", NEON_GREEN)])
        style.configure("Vertical.TScrollbar",   background=BG_LIGHTER, troughcolor=BG_DARK)
        style.configure("Horizontal.TScrollbar", background=BG_LIGHTER, troughcolor=BG_DARK)
        style.configure("TCombobox", fieldbackground=BG_LIGHTER, background=BG_LIGHTER,
                        foreground=NEON_GREEN, selectbackground=BG_LIGHTER)
        style.configure("TProgressbar", troughcolor=BG_LIGHTER,
                        background=NEON_GREEN, bordercolor=BG_DARK)
        for proto, color in PROTO_COLORS.items():
            self._tree.tag_configure(proto, foreground=color)

    # ── Details Panel ─────────────────────────
    def _build_details_panel(self, parent):
        frame = self._section(parent, "  ▸ PACKET DETAILS", height=195)
        self._detail_text = scrolledtext.ScrolledText(
            frame, bg=BG_PANEL, fg=TEXT_MID,
            font=FONT_MONO_SM, relief="flat",
            insertbackground=NEON_GREEN, state=tk.DISABLED, height=10)
        self._detail_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # ── Stats Panel ───────────────────────────
    def _build_stats_panel(self, parent):
        frame = self._section(parent, "  ▸ LIVE STATISTICS")
        inner = tk.Frame(frame, bg=BG_PANEL)
        inner.pack(fill=tk.X, padx=6, pady=6)

        self._stat_labels: dict[str, tk.Label] = {}
        counters = [
            ("TOTAL",     "0",  NEON_GREEN),
            ("PKT/SEC",   "0",  NEON_CYAN),
            ("ELAPSED",   "0s", TEXT_MID),
            ("ENCRYPTED", "0",  NEON_CYAN),
            ("HTTP/S",    "0",  NEON_ORANGE),
            ("TCP",       "0",  NEON_GREEN),
            ("UDP",       "0",  NEON_BLUE),
            ("DNS",       "0",  NEON_YELLOW),
            ("ICMP",      "0",  NEON_YELLOW),
            ("OTHER",     "0",  TEXT_DIM),
        ]
        for i, (label, val, color) in enumerate(counters):
            r, c = divmod(i, 2)
            tk.Label(inner, text=label + ":", bg=BG_PANEL, fg=TEXT_DIM,
                     font=("Courier New", 7)).grid(row=r*2,   column=c, sticky="w", padx=6)
            lbl = tk.Label(inner, text=val, bg=BG_PANEL, fg=color,
                           font=("Courier New", 13, "bold"))
            lbl.grid(row=r*2+1, column=c, sticky="w", padx=6, pady=(0, 6))
            self._stat_labels[label] = lbl

        tk.Label(frame, text="  PROTOCOL DISTRIBUTION",
                 bg=BG_PANEL, fg=TEXT_DIM, font=("Courier New", 7)).pack(anchor="w", padx=6)
        self._bar_canvas = tk.Canvas(frame, bg=BG_PANEL, height=100, highlightthickness=0)
        self._bar_canvas.pack(fill=tk.X, padx=6, pady=(2, 6))

    # ── Streams Panel ─────────────────────────
    def _build_streams_panel(self, parent):
        frame = self._section(parent, "  ▸ ACTIVE STREAMS")
        stream_cols = ("Flow", "Proto", "Pkts", "Data")
        self._stream_tree = ttk.Treeview(frame, columns=stream_cols,
                                          show="headings", selectmode="none", height=12)
        widths = {"Flow": 160, "Proto": 48, "Pkts": 44, "Data": 54}
        for col in stream_cols:
            self._stream_tree.heading(col, text=col)
            self._stream_tree.column(col, width=widths[col], anchor="w")
        self._stream_tree.configure(style="Treeview")
        self._stream_tree.tag_configure("heavy", foreground=NEON_YELLOW)
        vsb2 = ttk.Scrollbar(frame, orient="vertical", command=self._stream_tree.yview)
        self._stream_tree.configure(yscrollcommand=vsb2.set)
        self._stream_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0), pady=4)
        vsb2.pack(side=tk.LEFT, fill=tk.Y, pady=4, padx=(0, 4))

    # ── Status bar ────────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=BG_HEADER, height=22)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        self._status_var = tk.StringVar(value="  ● IDLE  |  Ready to capture packets")
        tk.Label(bar, textvariable=self._status_var, bg=BG_HEADER, fg=TEXT_MID,
                 font=("Courier New", 8), anchor="w").pack(side=tk.LEFT, padx=8)
        self._clock_lbl = tk.Label(bar, text="", bg=BG_HEADER, fg=TEXT_DIM,
                                   font=("Courier New", 8))
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
        self._set_status(f"  ● CAPTURING  |  {iface}  |  filter: '{bpf or 'none'}'")
        self._poll_packets()

    def stop_capture(self):
        if self.engine:
            self.engine.stop()
        if self._poll_job:
            self.root.after_cancel(self._poll_job)
            self._poll_job = None
        self._btn_start.config(state=tk.NORMAL)
        self._btn_stop.config(state=tk.DISABLED)
        self._set_status("  ■ STOPPED  |  Capture halted")

    def clear_packets(self):
        self._stored_packets.clear()
        self._item_pkt.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._set_detail("")
        if self.engine:
            self.engine.analyzer.reset()
        for iid in self._stream_tree.get_children():
            self._stream_tree.delete(iid)

    # ────────────────────────────────────────────
    #  Packet Poll Loop
    # ────────────────────────────────────────────
    def _poll_packets(self):
        if not self.engine:
            return
        try:
            batch = 0
            while batch < 40:
                try:
                    pkt = self.engine.packet_queue.get_nowait()
                    self._stored_packets.append(pkt)
                    self._add_table_row(pkt)
                    batch += 1
                except queue.Empty:
                    break
            if self.engine.is_running():
                self._update_stats(self.engine.get_stats())
                self._update_streams()
        except Exception as exc:
            print(f"[GUI] poll error: {exc}")
        finally:
            self._poll_job = self.root.after(80, self._poll_packets)

    # ────────────────────────────────────────────
    #  Table
    # ────────────────────────────────────────────
    def _add_table_row(self, pkt: dict):
        if not self._matches_filter(pkt):
            return
        proto  = pkt["protocol"]
        src    = pkt["src"] + (f":{pkt['sport']}" if pkt.get("sport") else "")
        dst    = pkt["dst"] + (f":{pkt['dport']}" if pkt.get("dport") else "")
        info   = pkt.get("tls_info") or pkt.get("http_info") or \
                 pkt.get("flags") or pkt.get("payload_ascii", "")[:50].replace(".", "") or ""
        tag    = proto.split()[0] if proto.split()[0] in PROTO_COLORS else "OTHER"

        iid = self._tree.insert("", "end",
            values=(pkt["index"], pkt["time"], src[:26], dst[:26],
                    proto, pkt.get("behavior", ""), pkt["length"], info[:50]),
            tags=(tag,))
        self._item_pkt[iid] = pkt

        children = self._tree.get_children()
        if len(children) > self.MAX_TABLE_ROWS:
            old = children[0]
            self._item_pkt.pop(old, None)
            self._tree.delete(old)

        if self._auto_scroll:
            self._tree.yview_moveto(1.0)

    # ── Stats ──────────────────────────────────
    def _update_stats(self, stats: dict):
        total  = stats["total"]
        protos = stats.get("protocols", {})

        self._stat_labels["TOTAL"].config(text=str(total))
        self._stat_labels["PKT/SEC"].config(text=str(stats.get("pps", 0)))
        self._stat_labels["ELAPSED"].config(text=f"{stats.get('elapsed', 0)}s")

        enc   = sum(c for p, c in protos.items() if any(x in p for x in ("TLS","HTTPS","QUIC")))
        httpc = sum(c for p, c in protos.items() if "HTTP" in p)
        self._stat_labels["ENCRYPTED"].config(text=str(enc))
        self._stat_labels["HTTP/S"].config(text=str(httpc))

        for label in ("TCP","UDP","DNS","ICMP","OTHER"):
            if label in self._stat_labels:
                self._stat_labels[label].config(text=str(protos.get(label, 0)))

        self._draw_bar_chart(protos, total)

    def _draw_bar_chart(self, protos: dict, total: int):
        c = self._bar_canvas
        c.delete("all")
        if not total:
            return
        w     = c.winfo_width() or 260
        items = sorted(protos.items(), key=lambda x: x[1], reverse=True)[:8]
        bw    = max(8, (w - 16) // max(len(items), 1) - 5)
        x, mh = 8, 72
        for proto, count in items:
            pct = count / total
            bh  = max(2, int(pct * mh))
            col = PROTO_COLORS.get(proto, TEXT_DIM)
            c.create_rectangle(x, 88, x+bw, 88-bh, fill=col, outline="")
            c.create_text(x+bw//2, 96, text=proto[:3], fill=col, font=("Courier New", 6))
            c.create_text(x+bw//2, 88-bh-7, text=str(count), fill=col, font=("Courier New", 6))
            x += bw + 5

    # ── Streams ────────────────────────────────
    def _update_streams(self):
        if not self.engine:
            return
        streams = self.engine.analyzer.get_top_streams(40)
        for iid in self._stream_tree.get_children():
            self._stream_tree.delete(iid)
        for s in streams:
            key    = s["key"]
            parts  = key.split(" ↔ ")
            label  = f"{parts[0][:18]}" if len(parts) > 0 else key[:20]
            data   = self._fmt_bytes(s["bytes"])
            tag    = "heavy" if s["bytes"] > 50_000 else ""
            self._stream_tree.insert("", "end",
                values=(label, s["proto"], s["packets"], data), tags=(tag,))

    @staticmethod
    def _fmt_bytes(b: int) -> str:
        if b >= 1_048_576: return f"{b/1_048_576:.1f}M"
        if b >= 1024:      return f"{b/1024:.1f}K"
        return f"{b}B"

    # ── Filter ────────────────────────────────
    def _matches_filter(self, pkt: dict) -> bool:
        pf = self._filter_proto_var.get()
        if pf != "ALL" and not pkt["protocol"].startswith(pf):
            return False
        q = self._search_var.get().lower().strip()
        if q:
            hay = f"{pkt['src']} {pkt['dst']} {pkt['protocol']} {pkt.get('behavior','')} {pkt.get('tls_info','')} {pkt.get('http_info','')}".lower()
            if q not in hay:
                return False
        return True

    def _apply_filter(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._item_pkt.clear()
        for pkt in self._stored_packets:
            self._add_table_row(pkt)

    # ── Row selection ─────────────────────────
    def _on_row_select(self, _):
        sel = self._tree.selection()
        if not sel:
            return
        pkt = self._item_pkt.get(sel[0])
        if pkt:
            self._selected_pkt = pkt
            self._set_detail(format_packet_details(pkt))

    def _on_row_double_click(self, _):
        if not self._selected_pkt:
            return
        popup = tk.Toplevel(self.root)
        popup.title(f"Packet #{self._selected_pkt['index']}  —  Details")
        popup.configure(bg=BG_DARK)
        popup.geometry("720x520")
        txt = scrolledtext.ScrolledText(popup, bg=BG_PANEL, fg=NEON_GREEN,
                                         font=FONT_MONO_SM, relief="flat")
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        txt.insert(tk.END, format_packet_details(self._selected_pkt))
        txt.config(state=tk.DISABLED)

    def _set_detail(self, text: str):
        self._detail_text.config(state=tk.NORMAL)
        self._detail_text.delete("1.0", tk.END)
        self._detail_text.insert(tk.END, text)
        self._detail_text.config(state=tk.DISABLED)

    # ── Column sort ───────────────────────────
    def _sort_by_column(self, col: str):
        data = [(self._tree.set(iid, col), iid) for iid in self._tree.get_children()]
        try:    data.sort(key=lambda t: float(t[0]))
        except: data.sort(key=lambda t: t[0].lower())
        for i, (_, iid) in enumerate(data):
            self._tree.move(iid, "", i)

    # ── Export ────────────────────────────────
    def _export_dialog(self):
        if not self.engine:
            messagebox.showinfo("No Data", "Start a capture session first.")
            return
        popup = tk.Toplevel(self.root)
        popup.title("Export Capture Data")
        popup.configure(bg=BG_DARK)
        popup.geometry("360x180")
        popup.resizable(False, False)
        tk.Label(popup, text="Choose Export Format",
                 bg=BG_DARK, fg=NEON_GREEN, font=FONT_HDR).pack(pady=(18, 10))
        bf = tk.Frame(popup, bg=BG_DARK)
        bf.pack()

        def do_pcap():
            path = filedialog.asksaveasfilename(defaultextension=".pcap",
                filetypes=[("PCAP","*.pcap"),("All","*.*")], title="Save PCAP")
            if path:
                ok = self.engine.export_pcap(path)
                popup.destroy()
                messagebox.showinfo("Export", f"{'Saved ✓' if ok else 'Failed'}: {path}")

        def do_json():
            path = filedialog.asksaveasfilename(defaultextension=".json",
                filetypes=[("JSON","*.json"),("All","*.*")], title="Save JSON")
            if path:
                import json
                data = [{k: v for k, v in p.items() if k != "raw_pkt"} for p in self._stored_packets]
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)
                popup.destroy()
                messagebox.showinfo("Export", f"Saved {len(data)} packets → {path}")

        self._make_btn(bf, "💾 Save PCAP", NEON_GREEN,  do_pcap).pack(side=tk.LEFT, padx=8)
        self._make_btn(bf, "📋 Save JSON", NEON_CYAN,   do_json).pack(side=tk.LEFT, padx=8)
        self._make_btn(bf, "✕ Cancel",    NEON_YELLOW, popup.destroy).pack(side=tk.LEFT, padx=8)

    # ── About Modal ───────────────────────────
    def _show_about(self):
        popup = tk.Toplevel(self.root)
        popup.title("About NetPhantom")
        popup.configure(bg=BG_DARK)
        popup.geometry("480x340")
        popup.resizable(False, False)

        border = tk.Frame(popup, bg=NEON_GREEN, bd=1)
        border.place(relx=0.03, rely=0.04, relwidth=0.94, relheight=0.92)
        inner = tk.Frame(border, bg=BG_PANEL)
        inner.place(relx=0.004, rely=0.006, relwidth=0.992, relheight=0.988)

        tk.Label(inner, text="⬡  NetPhantom", bg=BG_PANEL, fg=NEON_GREEN,
                 font=("Courier New", 18, "bold")).pack(pady=(18, 2))
        tk.Label(inner, text="Network Packet Sniffer & Deep Packet Inspector",
                 bg=BG_PANEL, fg=TEXT_MID, font=("Courier New", 10)).pack()
        tk.Frame(inner, bg=ACCENT_LINE, height=1).pack(fill=tk.X, padx=20, pady=14)

        rows = [
            ("Version",  "v2.0"),
            ("Author",   "Lucky"),
            ("Category", "Cybersecurity Portfolio Project"),
            ("Engine",   "Scapy + Tkinter"),
            ("Platform", "Windows / Linux"),
            ("License",  "Educational Use Only"),
        ]
        for label, val in rows:
            row = tk.Frame(inner, bg=BG_PANEL)
            row.pack(fill=tk.X, padx=24, pady=2)
            tk.Label(row, text=f"{label}:", bg=BG_PANEL, fg=TEXT_DIM,
                     font=("Courier New", 9), width=12, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=val, bg=BG_PANEL, fg=NEON_CYAN,
                     font=("Courier New", 9, "bold")).pack(side=tk.LEFT)

        tk.Frame(inner, bg=ACCENT_LINE, height=1).pack(fill=tk.X, padx=20, pady=10)
        self._make_btn(inner, "  Close  ", NEON_GREEN, popup.destroy).pack(pady=4)

    # ── Shortcuts ─────────────────────────────
    def _bind_shortcuts(self):
        self.root.bind("<F5>",        lambda e: self.start_capture())
        self.root.bind("<F6>",        lambda e: self.stop_capture())
        self.root.bind("<Control-e>", lambda e: self._export_dialog())
        self.root.bind("<Control-f>", lambda e: self._search_entry.focus_set())
        self.root.bind("<Control-l>", lambda e: self.clear_packets())
        self.root.bind("<Escape>",    lambda e: self.stop_capture())

    # ── Helpers ───────────────────────────────
    def _section(self, parent, title: str, height: int = None) -> tk.Frame:
        outer = tk.Frame(parent, bg=BG_PANEL, bd=0, relief="flat")
        if height:
            outer.pack(fill=tk.X, pady=2)
            outer.config(height=height)
            outer.pack_propagate(False)
        else:
            outer.pack(fill=tk.BOTH, expand=True, pady=2)
        tk.Label(outer, text=title, bg=BG_PANEL, fg=NEON_CYAN,
                 font=("Courier New", 8, "bold")).pack(anchor="w", padx=4, pady=(4, 0))
        tk.Frame(outer, bg=ACCENT_LINE, height=1).pack(fill=tk.X, padx=4)
        return outer

    def _make_btn(self, parent, text: str, color: str, cmd) -> tk.Button:
        btn = tk.Button(parent, text=text, command=cmd,
                        bg=BG_LIGHTER, fg=color,
                        activebackground=BG_PANEL, activeforeground=color,
                        font=("Courier New", 9, "bold"), relief="flat",
                        bd=0, padx=9, pady=4, cursor="hand2")
        btn.pack(side=tk.LEFT, padx=3, pady=6)
        btn.bind("<Enter>", lambda e, b=btn: b.config(bg=BG_PANEL))
        btn.bind("<Leave>", lambda e, b=btn: b.config(bg=BG_LIGHTER))
        return btn

    def _set_status(self, msg: str):
        self._status_var.set(msg)

    def _update_clock(self):
        self._clock_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._update_clock)

    def _show_warning(self):
        msg = (
            "⚠  ETHICAL USE WARNING\n\n"
            "This tool is for AUTHORIZED use ONLY.\n"
            "Capturing traffic without permission is illegal.\n\n"
            "By proceeding you confirm you have full authorization\n"
            "to monitor the target network.\n\n"
            "Run as Administrator / root for packet capture."
        )
        messagebox.showwarning("NetPhantom — Ethical Use", msg)

    def on_close(self):
        self.stop_capture()
        self.root.destroy()


# ──────────────────────────────────────────────
#  Launch
# ──────────────────────────────────────────────
def run_gui():
    show_splash()
    root = tk.Tk()
    app  = PacketSnifferGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
