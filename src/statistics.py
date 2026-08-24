"""
statistics.py
-------------
Tracks live protocol statistics during a capture session and renders a
clean summary report when capture stops.

Author: CodeAlpha Internship Project
"""

from src.utils import format_bytes


class CaptureStatistics:
    """Maintains running counters for a packet capture session."""

    def __init__(self):
        self.total_packets = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.arp_count = 0
        self.other_count = 0
        self.total_bytes = 0

    def record(self, protocol: str, length: int):
        """
        Update counters based on a newly analyzed packet.

        Args:
            protocol: The protocol name as determined by packet_analyzer
                       ("TCP", "UDP", "ICMP", "ARP", or "OTHER").
            length: The length in bytes of the packet.
        """
        self.total_packets += 1
        self.total_bytes += length

        protocol = protocol.upper()
        if protocol == "TCP":
            self.tcp_count += 1
        elif protocol == "UDP":
            self.udp_count += 1
        elif protocol == "ICMP":
            self.icmp_count += 1
        elif protocol == "ARP":
            self.arp_count += 1
        else:
            self.other_count += 1

    def reset(self):
        """Reset all counters to zero, e.g. before starting a new capture."""
        self.__init__()

    def summary(self) -> str:
        """Return a formatted, human-readable statistics summary."""
        lines = [
            "=" * 42,
            "           CAPTURE STATISTICS SUMMARY",
            "=" * 42,
            f"Total Packets Captured : {self.total_packets}",
            f"  TCP Packets   : {self.tcp_count}",
            f"  UDP Packets   : {self.udp_count}",
            f"  ICMP Packets  : {self.icmp_count}",
            f"  ARP Packets   : {self.arp_count}",
            f"  Other Packets : {self.other_count}",
            f"Total Data Captured     : {format_bytes(self.total_bytes)}",
            "=" * 42,
        ]
        return "\n".join(lines)
