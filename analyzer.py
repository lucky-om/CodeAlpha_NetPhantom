



"""
analyzer.py - Packet Parsing and Analysis Module
NetPhantom — Network Packet Sniffer Tool
Author: Lucky | Cybersecurity Portfolio Project
"""

import time
import ipaddress
from datetime import datetime
from collections import defaultdict
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Ether

# Attempt to load TLS and HTTP modules
try:
    from scapy.all import load_layer
    load_layer("tls")
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLS_Ext_ServerName
    HAS_TLS = True
except ImportError:
    HAS_TLS = False

try:
    load_layer("http")
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False


# ─────────────────────────────────────────────
#  Constants & Settings
# ─────────────────────────────────────────────
SUSPICIOUS_THRESHOLDS = {
    "port_scan_count": 15,          # SYN packets to different ports from same IP
    "dos_pps": 100,                 # Packets per second from single IP
    "icmp_flood_count": 50,         # ICMP packets per second from single IP
    "dns_query_count": 30,          # DNS queries per second from single IP
}


# ─────────────────────────────────────────────
#  Helper: Smart Classification
# ─────────────────────────────────────────────
def categorize_ip(ip_str: str) -> str:
    """Classify an IP address as Local, Broadcast, Multicast, or External."""
    if ip_str == "N/A" or not ip_str:
        return "Unknown"
    
    # Handle MAC Broadcasts masked as IP
    if ip_str.lower() == "ff:ff:ff:ff:ff:ff" or ip_str == "255.255.255.255":
        return "Broadcast"

    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_multicast:
            return "Multicast"
        if ip.is_private or ip.is_loopback:
            return "Local"
        return "External"
    except ValueError:
        return "Unknown"


# ─────────────────────────────────────────────
#  Core Packet Analyzer
# ─────────────────────────────────────────────
class PacketAnalyzer:
    """Parses raw Scapy packets into structured dictionaries (DPI applied)."""

    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(set)          # IP → set of dst ports
        self.ip_timestamps = defaultdict(list)      # IP → list of timestamps
        self.alerts = []

    def parse(self, pkt) -> dict:
        """Parse a scapy packet and return a structured dictionary."""
        self.packet_count += 1
        now = time.time()
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        info = {
            "index": self.packet_count,
            "time": ts,
            "timestamp": now,
            "src": "N/A",
            "dst": "N/A",
            "protocol": "OTHER",
            "length": len(pkt),
            "sport": None,
            "dport": None,
            "flags": None,
            "ttl": None,
            "payload_ascii": "",
            "payload_hex": "",
            "summary": pkt.summary(),
            "raw_pkt": pkt,
            
            # Smart Data
            "classification": "Unknown",
            "is_encrypted": False,
            "tls_info": None,
            "http_info": None,
        }

        # ── Layer 2: Ethernet ──────────────────
        if pkt.haslayer(Ether):
            info["eth_src"] = pkt[Ether].src
            info["eth_dst"] = pkt[Ether].dst

        # ── Layer 3: IP / IPv6 ─────────────────
        if pkt.haslayer(IP):
            info["src"] = pkt[IP].src
            info["dst"] = pkt[IP].dst
            info["ttl"] = pkt[IP].ttl
            self.ip_stats[info["src"]] += 1
            self.ip_timestamps[info["src"]].append(now)

        elif pkt.haslayer(IPv6):
            info["src"] = pkt[IPv6].src
            info["dst"] = pkt[IPv6].dst
            info["protocol"] = "IPv6"

        # ── Network Boundary Classification ────
        src_cat = categorize_ip(info["src"])
        dst_cat = categorize_ip(info["dst"])
        if dst_cat == "Broadcast":
            info["classification"] = f"{src_cat} → Broadcast"
        elif dst_cat == "Multicast":
            info["classification"] = f"{src_cat} → Multicast"
        else:
            info["classification"] = f"{src_cat} ↔ {dst_cat}"

        # ── Layer 3: ARP ───────────────────────
        if pkt.haslayer(ARP):
            info["src"] = pkt[ARP].psrc
            info["dst"] = pkt[ARP].pdst
            info["protocol"] = "ARP"

        # ── Layer 4: Transport ─────────────────
        if pkt.haslayer(TCP):
            info["protocol"] = "TCP"
            info["sport"] = pkt[TCP].sport
            info["dport"] = pkt[TCP].dport
            info["flags"] = str(pkt[TCP].flags)
            if info["src"] != "N/A":
                self.port_stats[info["src"]].add(pkt[TCP].dport)

        elif pkt.haslayer(UDP):
            info["protocol"] = "UDP"
            info["sport"] = pkt[UDP].sport
            info["dport"] = pkt[UDP].dport

        elif pkt.haslayer(ICMP):
            info["protocol"] = "ICMP"

        # ── Application / DPI Layer ────────────
        app_proto = None
        
        # DNS
        if pkt.haslayer(DNS):
            app_proto = "DNS"
            try:
                qn = pkt[DNS].qd.qname.decode('utf-8')
                info["tls_info"] = f"Query: {qn}"   # Misuse tls field for display clarity
            except Exception:
                pass

        # QUIC (Transport over UDP port 443)
        elif info["protocol"] == "UDP" and (info["sport"] == 443 or info["dport"] == 443):
            app_proto = "QUIC"
            info["is_encrypted"] = True

        # HTTP Parsing
        elif HAS_HTTP and (pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse)):
            app_proto = "HTTP"
            if pkt.haslayer(HTTPRequest):
                method = pkt[HTTPRequest].Method.decode('utf-8', 'ignore') if pkt[HTTPRequest].Method else ""
                host = pkt[HTTPRequest].Host.decode('utf-8', 'ignore') if pkt[HTTPRequest].Host else ""
                path = pkt[HTTPRequest].Path.decode('utf-8', 'ignore') if pkt[HTTPRequest].Path else ""
                info["http_info"] = f"{method} {host}{path}"
        elif info["protocol"] == "TCP" and (info["sport"] in (80, 8080) or info["dport"] in (80, 8080)):
            app_proto = "HTTP"

        # TLS / HTTPS Parsing
        elif HAS_TLS and pkt.haslayer(TLS):
            app_proto = "TLS"
            info["is_encrypted"] = True
            
            if pkt.haslayer(TLSClientHello):
                info["protocol"] = "TLS ClientHello"
                # Extract SNI
                sni = "Unknown Domain"
                version = "TLS"
                ch = pkt[TLSClientHello]
                if hasattr(ch, "version"):
                    v_val = ch.version
                    if v_val == 0x0303: version = "TLS 1.2"
                    elif v_val == 0x0304: version = "TLS 1.3"
                if ch.ext:
                    for ext in ch.ext:
                        if isinstance(ext, TLS_Ext_ServerName) and ext.servernames:
                            sni = ext.servernames[0].servername.decode('utf-8', 'ignore')
                info["tls_info"] = f"SNI: {sni} | {version}"
                
            elif pkt.haslayer(TLSServerHello):
                info["protocol"] = "TLS ServerHello"
                info["tls_info"] = "Handshake Reply"
                
        elif info["protocol"] == "TCP" and (info["sport"] == 443 or info["dport"] == 443):
            app_proto = "HTTPS"
            info["is_encrypted"] = True

        # Override protocol if application layer detected
        if app_proto:
            if info["protocol"] not in ("TLS ClientHello", "TLS ServerHello"):
                info["protocol"] = app_proto

        # ── Payload Extraction (Hex & ASCII) ───
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            # ASCII: replace non-printable with dots or spaces
            ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
            info["payload_ascii"] = ascii_repr[:300]
            
            # Hex separated by space
            hex_repr = " ".join(f"{b:02x}" for b in raw)
            info["payload_hex"] = hex_repr[:400]

        # ── Update Stats ───────────────────────
        self.protocol_stats[info["protocol"].split()[0]] += 1

        # ── Run Threat Detection ───────────────
        alert = self._detect_threats(info, now)
        if alert:
            self.alerts.append(alert)
            info["alert"] = alert

        return info

    def _detect_threats(self, info: dict, now: float) -> str | None:
        src = info["src"]
        if src == "N/A":
            return None

        # ── Port Scan Detection ────────────────
        if len(self.port_stats.get(src, set())) > SUSPICIOUS_THRESHOLDS["port_scan_count"]:
            return f"⚠ PORT SCAN detected from {src} ({len(self.port_stats[src])} ports)"

        # ── High-Rate Detection (DoS/Flood) ────
        timestamps = self.ip_timestamps.get(src, [])
        recent = [t for t in timestamps if now - t <= 1.0]
        self.ip_timestamps[src] = recent

        if len(recent) > SUSPICIOUS_THRESHOLDS["dos_pps"]:
            proto = info["protocol"]
            if "ICMP" in proto and len(recent) > SUSPICIOUS_THRESHOLDS["icmp_flood_count"]:
                return f"⚠ ICMP FLOOD from {src} ({len(recent)} pkt/s)"
            elif "DNS" in proto and len(recent) > SUSPICIOUS_THRESHOLDS["dns_query_count"]:
                return f"⚠ DNS FLOOD from {src} ({len(recent)} pkt/s)"
            else:
                return f"⚠ HIGH TRAFFIC from {src} ({len(recent)} pkt/s)"

        return None

    def get_stats(self) -> dict:
        return {
            "total": self.packet_count,
            "protocols": dict(self.protocol_stats),
            "top_ips": sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10],
            "alerts": self.alerts[-20:],
        }

    def reset(self):
        self.packet_count = 0
        self.protocol_stats.clear()
        self.ip_stats.clear()
        self.port_stats.clear()
        self.ip_timestamps.clear()
        self.alerts.clear()


# ─────────────────────────────────────────────
#  Packet Detail Formatter (Improved)
# ─────────────────────────────────────────────
def format_packet_details(pkt_info: dict) -> str:
    """Return a human-readable multi-line detailed packet breakdown."""
    lines = [
        "╔═════════════════════════════════════════════════════════════╗",
        f"  PACKET #{pkt_info['index']}  |  {pkt_info['time']}",
        "╚═════════════════════════════════════════════════════════════╝",
        "",
        f"  PROTOCOL  : {pkt_info['protocol']}",
        f"  SRC       : {pkt_info['src']}" + (f":{pkt_info['sport']}" if pkt_info.get("sport") else ""),
        f"  DST       : {pkt_info['dst']}" + (f":{pkt_info['dport']}" if pkt_info.get("dport") else ""),
        f"  LENGTH    : {pkt_info['length']} bytes",
        f"  BOUNDARY  : {pkt_info['classification']}",
        f"  ENCRYPTED : {'YES ' if pkt_info['is_encrypted'] else 'NO '}",
    ]

    if pkt_info.get("tls_info"):
        lines.append(f"  TLS/INFO  : {pkt_info['tls_info']}")
    if pkt_info.get("http_info"):
        lines.append(f"  HTTP CALL : {pkt_info['http_info']}")

    if pkt_info.get("ttl") is not None:
        lines.append(f"  TTL       : {pkt_info['ttl']}")
    if pkt_info.get("flags") and pkt_info["flags"] != "None":
        lines.append(f"  TCP FLAGS : {pkt_info['flags']}")

    # Threat Injection
    if pkt_info.get("alert"):
        lines += ["", f"  🚨 ALERT: {pkt_info['alert']}"]

    # ASCII and Hex Payloads
    if pkt_info.get("payload_ascii") or pkt_info.get("payload_hex"):
        lines += ["", "  ── PAYLOAD: ASCII ───────────────────────────"]
        # chunk into 60 char lines
        payload = pkt_info['payload_ascii']
        for i in range(0, len(payload), 60):
            lines.append(f"  {payload[i:i+60]}")
            
        lines += ["", "  ── PAYLOAD: HEX ─────────────────────────────"]
        hexd = pkt_info['payload_hex']
        # chunk into 45 chars (roughly 15 bytes)
        for i in range(0, len(hexd), 45):
            lines.append(f"  {hexd[i:i+45]}")

    lines += ["", "  ── RAW SCAPY SUMMARY ────────────────────────"]
    lines.append(f"  {pkt_info['summary']}")
    
    return "\n".join(lines)
