"""
analyzer.py - Deep Packet Inspection & Stream Tracking Module
NetPhantom — Network Packet Sniffer Tool
Author: Lucky | Cybersecurity Portfolio Project
"""

import time
import ipaddress
from datetime import datetime
from collections import defaultdict
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Ether

# ─────────────────────────────────────────────
#  Optional Layer Loading
# ─────────────────────────────────────────────
try:
    from scapy.all import load_layer
    load_layer("tls")
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLS_Ext_ServerName
    HAS_TLS = True
except Exception:
    HAS_TLS = False

try:
    from scapy.all import load_layer
    load_layer("http")
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAS_HTTP = True
except Exception:
    HAS_HTTP = False


# ─────────────────────────────────────────────
#  Helper: IP Classification
# ─────────────────────────────────────────────
def categorize_ip(ip_str: str) -> str:
    """Classify an IP address as Local, Broadcast, Multicast, or External."""
    if not ip_str or ip_str == "N/A":
        return "Unknown"
    if ip_str in ("255.255.255.255", "ff:ff:ff:ff:ff:ff"):
        return "Broadcast"
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_multicast:   return "Multicast"
        if ip.is_loopback:    return "Loopback"
        if ip.is_private:     return "Local"
        return "External"
    except ValueError:
        return "Unknown"


# ─────────────────────────────────────────────
#  Stream Key Helper
# ─────────────────────────────────────────────
def make_stream_key(info: dict) -> str:
    """Return a canonical bi-directional flow key."""
    src = f"{info['src']}:{info.get('sport') or 0}"
    dst = f"{info['dst']}:{info.get('dport') or 0}"
    # Ensure same key regardless of direction
    return " ↔ ".join(sorted([src, dst]))


# ─────────────────────────────────────────────
#  Core Packet Analyzer
# ─────────────────────────────────────────────
class PacketAnalyzer:
    """Parses raw Scapy packets into structured dicts with DPI and stream tracking."""

    def __init__(self):
        self.packet_count   = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats       = defaultdict(int)
        # Stream tracking: key → {packets, bytes, proto, last_seen}
        self.streams: dict[str, dict] = {}

    def parse(self, pkt) -> dict:
        self.packet_count += 1
        now = time.time()
        ts  = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        info = {
            "index":        self.packet_count,
            "time":         ts,
            "timestamp":    now,
            "src":          "N/A",
            "dst":          "N/A",
            "protocol":     "OTHER",
            "length":       len(pkt),
            "sport":        None,
            "dport":        None,
            "flags":        None,
            "ttl":          None,
            "payload_ascii":"",
            "payload_hex":  "",
            "summary":      pkt.summary(),
            "raw_pkt":      pkt,
            "classification":"Unknown",
            "is_encrypted": False,
            "tls_info":     None,
            "http_info":    None,
            "behavior":     "",
        }

        # ── L2 Ethernet ────────────────────────
        if pkt.haslayer(Ether):
            info["eth_src"] = pkt[Ether].src
            info["eth_dst"] = pkt[Ether].dst

        # ── L3 IP / IPv6 ───────────────────────
        if pkt.haslayer(IP):
            info["src"] = pkt[IP].src
            info["dst"] = pkt[IP].dst
            info["ttl"] = pkt[IP].ttl
            self.ip_stats[info["src"]] += 1

        elif pkt.haslayer(IPv6):
            info["src"]      = pkt[IPv6].src
            info["dst"]      = pkt[IPv6].dst
            info["protocol"] = "IPv6"

        # ── Boundary Classification ─────────────
        src_cat = categorize_ip(info["src"])
        dst_cat = categorize_ip(info["dst"])
        if dst_cat == "Broadcast":
            info["classification"] = f"{src_cat} → Broadcast"
        elif dst_cat == "Multicast":
            info["classification"] = f"{src_cat} → Multicast"
        else:
            info["classification"] = f"{src_cat} ↔ {dst_cat}"

        # ── L3 ARP ─────────────────────────────
        if pkt.haslayer(ARP):
            info["src"]      = pkt[ARP].psrc
            info["dst"]      = pkt[ARP].pdst
            info["protocol"] = "ARP"

        # ── L4 Transport ───────────────────────
        if pkt.haslayer(TCP):
            info["protocol"] = "TCP"
            info["sport"]    = pkt[TCP].sport
            info["dport"]    = pkt[TCP].dport
            info["flags"]    = str(pkt[TCP].flags)

        elif pkt.haslayer(UDP):
            info["protocol"] = "UDP"
            info["sport"]    = pkt[UDP].sport
            info["dport"]    = pkt[UDP].dport

        elif pkt.haslayer(ICMP):
            info["protocol"] = "ICMP"

        # ── DPI: Application Layer ──────────────
        app_proto = None

        if pkt.haslayer(DNS):
            app_proto = "DNS"
            try:
                qn = pkt[DNS].qd.qname.decode("utf-8", "ignore")
                info["tls_info"] = f"Query: {qn}"
            except Exception:
                pass

        elif info["protocol"] == "UDP" and (info["sport"] == 443 or info["dport"] == 443):
            app_proto = "QUIC"
            info["is_encrypted"] = True

        elif HAS_HTTP and (pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse)):
            app_proto = "HTTP"
            if pkt.haslayer(HTTPRequest):
                method = pkt[HTTPRequest].Method.decode("utf-8", "ignore") if pkt[HTTPRequest].Method else ""
                host   = pkt[HTTPRequest].Host.decode("utf-8", "ignore")   if pkt[HTTPRequest].Host   else ""
                path   = pkt[HTTPRequest].Path.decode("utf-8", "ignore")   if pkt[HTTPRequest].Path   else ""
                info["http_info"] = f"{method} {host}{path}"

        elif info["protocol"] == "TCP" and (info["sport"] in (80, 8080) or info["dport"] in (80, 8080)):
            app_proto = "HTTP"

        elif HAS_TLS and pkt.haslayer(TLS):
            app_proto            = "TLS"
            info["is_encrypted"] = True
            if pkt.haslayer(TLSClientHello):
                info["protocol"] = "TLS ClientHello"
                sni = "Unknown Domain"; version = "TLS"
                ch  = pkt[TLSClientHello]
                if hasattr(ch, "version"):
                    if ch.version == 0x0303: version = "TLS 1.2"
                    elif ch.version == 0x0304: version = "TLS 1.3"
                if ch.ext:
                    for ext in ch.ext:
                        if isinstance(ext, TLS_Ext_ServerName) and ext.servernames:
                            sni = ext.servernames[0].servername.decode("utf-8", "ignore")
                info["tls_info"] = f"SNI: {sni} | {version}"
            elif pkt.haslayer(TLSServerHello):
                info["protocol"] = "TLS ServerHello"
                info["tls_info"] = "Handshake Reply"

        elif info["protocol"] == "TCP" and (info["sport"] == 443 or info["dport"] == 443):
            app_proto            = "HTTPS"
            info["is_encrypted"] = True

        if app_proto and info["protocol"] not in ("TLS ClientHello", "TLS ServerHello"):
            info["protocol"] = app_proto

        # ── Payload ─────────────────────────────
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            info["payload_ascii"] = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)[:300]
            info["payload_hex"]   = " ".join(f"{b:02x}" for b in raw)[:500]

        # ── Behavior Tagging ────────────────────
        info["behavior"] = self._determine_behavior(info)

        # ── Protocol Stats ──────────────────────
        self.protocol_stats[info["protocol"].split()[0]] += 1

        # ── Stream Tracking ─────────────────────
        if info["src"] != "N/A":
            key = make_stream_key(info)
            if key not in self.streams:
                self.streams[key] = {
                    "proto":   info["protocol"].split()[0],
                    "packets": 0,
                    "bytes":   0,
                    "key":     key,
                }
            s = self.streams[key]
            s["packets"]   += 1
            s["bytes"]     += info["length"]
            s["last_seen"]  = ts

        return info

    # ── Behavior Tagger ────────────────────────
    def _determine_behavior(self, info: dict) -> str:
        proto  = info.get("protocol", "")
        sport  = info.get("sport")
        dport  = info.get("dport")
        payload = info.get("payload_ascii", "").lower()

        browser = ""
        if "brave"   in payload: browser = " (Brave)"
        elif "chrome" in payload: browser = " (Chrome)"
        elif "firefox" in payload: browser = " (Firefox)"
        elif "safari"  in payload: browser = " (Safari)"
        elif "edge"    in payload: browser = " (Edge)"

        if any(x in proto for x in ("HTTP", "TLS", "QUIC")) or sport in (80, 443) or dport in (80, 443):
            return f"Web Browsing{browser}"
        if proto == "DNS" or sport == 53 or dport == 53:
            return "DNS Resolution"
        if sport in (1900, 5353, 5355) or dport in (1900, 5353, 5355):
            return "Local Discovery"
        if proto == "ICMP":
            return "Network Ping"
        if sport == 22 or dport == 22:
            return "SSH Remote Shell"
        if sport in (20, 21) or dport in (20, 21):
            return "File Transfer (FTP)"
        if sport == 3389 or dport == 3389:
            return "Remote Desktop"
        if proto == "ARP":
            return "ARP Resolution"
        return f"Network Traffic ({proto})"

    def get_stats(self) -> dict:
        return {
            "total":     self.packet_count,
            "protocols": dict(self.protocol_stats),
            "top_ips":   sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10],
            "streams":   sorted(self.streams.values(), key=lambda s: s["bytes"], reverse=True)[:50],
        }

    def get_top_streams(self, n: int = 40) -> list:
        return sorted(self.streams.values(), key=lambda s: s["bytes"], reverse=True)[:n]

    def reset(self):
        self.packet_count = 0
        self.protocol_stats.clear()
        self.ip_stats.clear()
        self.streams.clear()


# ─────────────────────────────────────────────
#  Packet Detail Formatter
# ─────────────────────────────────────────────
def format_packet_details(pkt_info: dict) -> str:
    """Return a clean multi-line detailed packet report."""
    lines = [
        "╔═════════════════════════════════════════════════════════════╗",
        f"  PACKET #{pkt_info['index']}  ·  {pkt_info['time']}",
        "╚═════════════════════════════════════════════════════════════╝",
        "",
        f"  BEHAVIOR   : {pkt_info.get('behavior', 'Unknown')}",
        f"  PROTOCOL   : {pkt_info['protocol']}",
        f"  SRC        : {pkt_info['src']}" + (f":{pkt_info['sport']}" if pkt_info.get("sport") else ""),
        f"  DST        : {pkt_info['dst']}" + (f":{pkt_info['dport']}" if pkt_info.get("dport") else ""),
        f"  LENGTH     : {pkt_info['length']} bytes",
        f"  BOUNDARY   : {pkt_info['classification']}",
        f"  ENCRYPTED  : {'YES ✓' if pkt_info['is_encrypted'] else 'NO'}",
    ]

    if pkt_info.get("ttl") is not None:
        lines.append(f"  TTL        : {pkt_info['ttl']}")
    if pkt_info.get("flags") and pkt_info["flags"] != "None":
        lines.append(f"  TCP FLAGS  : {pkt_info['flags']}")
    if pkt_info.get("tls_info"):
        lines.append(f"  TLS INFO   : {pkt_info['tls_info']}")
    if pkt_info.get("http_info"):
        lines.append(f"  HTTP       : {pkt_info['http_info']}")

    if pkt_info.get("payload_ascii"):
        lines += ["", "  ── PAYLOAD · ASCII ───────────────────────────"]
        pl = pkt_info["payload_ascii"]
        for i in range(0, len(pl), 64):
            lines.append(f"  {pl[i:i+64]}")

    if pkt_info.get("payload_hex"):
        lines += ["", "  ── PAYLOAD · HEX ─────────────────────────────"]
        hx = pkt_info["payload_hex"]
        for i in range(0, len(hx), 48):
            lines.append(f"  {hx[i:i+48]}")

    lines += ["", "  ── RAW SUMMARY ───────────────────────────────"]
    lines.append(f"  {pkt_info['summary']}")
    return "\n".join(lines)
