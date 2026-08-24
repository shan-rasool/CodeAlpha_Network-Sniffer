"""
filters.py
----------
Handles configuration and application of simple, optional packet filters:
by protocol, source IP, destination IP, and port. Filters are applied
against the structured PacketInfo produced by packet_analyzer, as well
as being convertible into a Scapy/BPF filter string for efficient
capture-time filtering where possible.

Author: CodeAlpha Internship Project
"""

from dataclasses import dataclass
from typing import Optional

from src.utils import (
    is_valid_ipv4,
    is_valid_port,
    is_valid_protocol,
    print_error,
    print_success,
    print_info,
)


@dataclass
class PacketFilter:
    """Holds the currently configured (optional) packet filter criteria."""

    protocol: Optional[str] = None      # "TCP", "UDP", "ICMP", "ARP"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None

    def is_active(self) -> bool:
        """Return True if any filter criterion has been configured."""
        return any([self.protocol, self.source_ip, self.destination_ip, self.port])

    def clear(self):
        """Reset all filter criteria."""
        self.protocol = None
        self.source_ip = None
        self.destination_ip = None
        self.port = None

    def matches(self, packet_info) -> bool:
        """
        Check whether a given PacketInfo object satisfies all currently
        configured filter criteria (logical AND across active filters).

        Args:
            packet_info: A PacketInfo instance from packet_analyzer.

        Returns:
            True if the packet passes the filter, False otherwise.
        """
        if self.protocol and packet_info.protocol.upper() != self.protocol.upper():
            return False

        if self.source_ip and packet_info.src_ip != self.source_ip:
            return False

        if self.destination_ip and packet_info.dst_ip != self.destination_ip:
            return False

        if self.port is not None:
            ports = {packet_info.src_port, packet_info.dst_port}
            if self.port not in ports:
                return False

        return True

    def to_bpf_string(self) -> Optional[str]:
        """
        Convert the current filter into a Berkeley Packet Filter (BPF)
        string that can be passed directly to Scapy's sniff() for more
        efficient, kernel-level filtering. Returns None if no protocol
        or IP/port filter can be meaningfully expressed in BPF (ARP-only
        combos with ports are skipped since ARP has no ports).

        Returns:
            A BPF filter string, or None if not applicable.
        """
        clauses = []

        if self.protocol:
            proto = self.protocol.lower()
            if proto in ("tcp", "udp", "icmp", "arp"):
                clauses.append(proto)

        if self.source_ip:
            clauses.append(f"src host {self.source_ip}")

        if self.destination_ip:
            clauses.append(f"dst host {self.destination_ip}")

        if self.port is not None and self.protocol and self.protocol.lower() != "arp":
            clauses.append(f"port {self.port}")

        if not clauses:
            return None

        return " and ".join(clauses)

    def describe(self) -> str:
        """Return a human-readable description of the active filter."""
        if not self.is_active():
            return "No filter active (capturing all supported protocols)."

        parts = []
        if self.protocol:
            parts.append(f"Protocol={self.protocol.upper()}")
        if self.source_ip:
            parts.append(f"SourceIP={self.source_ip}")
        if self.destination_ip:
            parts.append(f"DestinationIP={self.destination_ip}")
        if self.port is not None:
            parts.append(f"Port={self.port}")
        return "Active filter: " + ", ".join(parts)


def configure_filter_interactively(current_filter: PacketFilter) -> PacketFilter:
    """
    Interactively prompt the user to configure filter criteria, with
    input validation and helpful error messages.

    Args:
        current_filter: The existing PacketFilter to modify (or replace).

    Returns:
        The updated PacketFilter instance.
    """
    print_info("Configure packet filter. Press Enter to skip any field.")
    print_info("Press Enter on all fields to clear the current filter.")

    new_filter = PacketFilter()

    protocol_input = input("Protocol filter (TCP/UDP/ICMP/ARP): ").strip()
    if protocol_input:
        if is_valid_protocol(protocol_input):
            new_filter.protocol = protocol_input.upper()
        else:
            print_error("Invalid protocol. Must be one of TCP, UDP, ICMP, ARP. Skipping protocol filter.")

    src_ip_input = input("Source IP filter (e.g. 192.168.1.10): ").strip()
    if src_ip_input:
        if is_valid_ipv4(src_ip_input):
            new_filter.source_ip = src_ip_input
        else:
            print_error("Invalid source IP address format. Skipping source IP filter.")

    dst_ip_input = input("Destination IP filter (e.g. 192.168.1.20): ").strip()
    if dst_ip_input:
        if is_valid_ipv4(dst_ip_input):
            new_filter.destination_ip = dst_ip_input
        else:
            print_error("Invalid destination IP address format. Skipping destination IP filter.")

    port_input = input("Port filter (0-65535): ").strip()
    if port_input:
        if is_valid_port(port_input):
            new_filter.port = int(port_input)
        else:
            print_error("Invalid port number. Must be between 0 and 65535. Skipping port filter.")

    if new_filter.is_active():
        print_success("Filter updated successfully.")
    else:
        print_info("No valid filter criteria entered. Filter cleared.")

    print_info(new_filter.describe())
    return new_filter
