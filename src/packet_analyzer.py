"""
packet_analyzer.py
-------------------
Responsible for inspecting a captured Scapy packet and extracting a clean,
structured summary of its contents: IP addresses, protocol, ports, flags,
size, timestamp, and (optionally) a safely-rendered payload preview.

This module never attempts to decrypt or interpret encrypted payloads; it
only renders the raw bytes that are already visible on the wire.

Author: CodeAlpha Internship Project
"""

from dataclasses import dataclass, field
from typing import Optional

from src.utils import get_current_timestamp, safe_payload_preview

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Raw
except ImportError:
    # Scapy may not be installed yet; sniffer.py handles this gracefully
    # at startup. We still allow this module to be imported for unit
    # testing purposes without crashing on import.
    IP = IPv6 = TCP = UDP = ICMP = ARP = Raw = None


# TCP flag bit meanings, used to render human-readable flag strings.
TCP_FLAGS_MAP = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


@dataclass
class PacketInfo:
    """Structured representation of a single analyzed packet."""

    packet_number: int
    timestamp: str
    protocol: str
    length: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    icmp_type: Optional[str] = None
    icmp_code: Optional[str] = None
    payload_preview: Optional[str] = None
    raw_packet: object = field(default=None, repr=False)

    def to_display_string(self, show_payload: bool = False) -> str:
        """Render this packet's information as a formatted, readable block."""
        lines = [
            f"Packet #{self.packet_number}  |  {self.timestamp}",
            f"  Protocol   : {self.protocol}",
            f"  Length     : {self.length} bytes",
        ]

        if self.src_ip or self.dst_ip:
            lines.append(f"  Source IP      : {self.src_ip or 'N/A'}")
            lines.append(f"  Destination IP : {self.dst_ip or 'N/A'}")

        if self.src_port is not None or self.dst_port is not None:
            lines.append(f"  Source Port      : {self.src_port if self.src_port is not None else 'N/A'}")
            lines.append(f"  Destination Port : {self.dst_port if self.dst_port is not None else 'N/A'}")

        if self.tcp_flags:
            lines.append(f"  TCP Flags  : {self.tcp_flags}")

        if self.icmp_type is not None:
            lines.append(f"  ICMP Type/Code : {self.icmp_type}/{self.icmp_code}")

        if show_payload:
            preview = self.payload_preview or "<no payload data available>"
            lines.append(f"  Payload    : {preview}")

        return "\n".join(lines)


def _decode_tcp_flags(flags_value) -> str:
    """Convert Scapy TCP flag characters into a readable, expanded string."""
    if flags_value is None:
        return ""
    flag_str = str(flags_value)
    decoded = [TCP_FLAGS_MAP.get(ch, ch) for ch in flag_str]
    return ",".join(decoded) if decoded else flag_str


def analyze_packet(packet, packet_number: int) -> PacketInfo:
    """
    Analyze a single Scapy packet and extract structured, display-ready
    information from it.

    Args:
        packet: The Scapy packet object captured from the wire.
        packet_number: Sequential number of this packet in the capture.

    Returns:
        A PacketInfo dataclass instance summarizing the packet.
    """
    timestamp = get_current_timestamp()
    length = len(packet)

    info = PacketInfo(
        packet_number=packet_number,
        timestamp=timestamp,
        protocol="OTHER",
        length=length,
        raw_packet=packet,
    )

    # --- ARP (no IP layer) ---
    if ARP is not None and packet.haslayer(ARP):
        arp_layer = packet[ARP]
        info.protocol = "ARP"
        info.src_ip = arp_layer.psrc
        info.dst_ip = arp_layer.pdst
        return info

    # --- IP-based protocols (TCP / UDP / ICMP) ---
    ip_layer = None
    if IP is not None and packet.haslayer(IP):
        ip_layer = packet[IP]
    elif IPv6 is not None and packet.haslayer(IPv6):
        ip_layer = packet[IPv6]

    if ip_layer is not None:
        info.src_ip = ip_layer.src
        info.dst_ip = ip_layer.dst

        if TCP is not None and packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            info.protocol = "TCP"
            info.src_port = int(tcp_layer.sport)
            info.dst_port = int(tcp_layer.dport)
            info.tcp_flags = _decode_tcp_flags(tcp_layer.flags)

        elif UDP is not None and packet.haslayer(UDP):
            udp_layer = packet[UDP]
            info.protocol = "UDP"
            info.src_port = int(udp_layer.sport)
            info.dst_port = int(udp_layer.dport)

        elif ICMP is not None and packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            info.protocol = "ICMP"
            info.icmp_type = str(icmp_layer.type)
            info.icmp_code = str(icmp_layer.code)

        else:
            info.protocol = "OTHER"

    # --- Payload extraction (safe preview only, no decryption attempts) ---
    if Raw is not None and packet.haslayer(Raw):
        try:
            raw_bytes = bytes(packet[Raw].load)
            info.payload_preview = safe_payload_preview(raw_bytes)
        except Exception:
            info.payload_preview = "<payload could not be read safely>"
    else:
        info.payload_preview = "<no payload data available (e.g. header-only or encrypted)>"

    return info
