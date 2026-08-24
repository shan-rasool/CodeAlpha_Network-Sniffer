"""
sniffer.py
----------
Core packet-capture engine for the Basic Network Sniffer project.

This module wraps Scapy's sniff() functionality with:
  - graceful handling of missing dependencies / permissions
  - live, formatted display of each captured packet
  - integration with statistics tracking and optional filters
  - PCAP export of the current capture session

IMPORTANT (Legal & Ethical Notice)
-----------------------------------
This tool is intended ONLY for educational purposes and authorized
network monitoring (your own machine, a lab environment, or a network
where you have explicit permission to capture traffic). Do not use this
tool to capture or inspect traffic on networks or systems without
explicit permission.

Author: CodeAlpha Internship Project
"""

import sys
import threading

from src.packet_analyzer import analyze_packet
from src.statistics import CaptureStatistics
from src.filters import PacketFilter
from src.utils import (
    print_error,
    print_warning,
    print_success,
    print_info,
    print_divider,
    ensure_directory,
    get_filename_timestamp,
)

CAPTURES_DIR = "captures"

# --------------------------------------------------------------------------
# Scapy import handling
# --------------------------------------------------------------------------
try:
    from scapy.all import sniff, AsyncSniffer, get_if_list, wrpcap, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkSniffer:
    """
    Encapsulates a single capture session: configuration (interface,
    filter, payload inspection toggle), live capture, and the resulting
    packet buffer for later export or statistics review.
    """

    def __init__(self):
        self.statistics = CaptureStatistics()
        self.packet_filter = PacketFilter()
        self.payload_inspection_enabled = False
        self.captured_packets = []      # raw Scapy packets, for PCAP export
        self.captured_infos = []        # analyzed PacketInfo objects
        self._packet_counter = 0
        self._lock = threading.RLock()
        self._async_sniffer = None
        self._is_capturing = False

    # ----------------------------------------------------------------
    # Dependency / environment checks
    # ----------------------------------------------------------------

    @staticmethod
    def check_scapy_available() -> bool:
        """Return True if Scapy is importable, printing guidance if not."""
        if not SCAPY_AVAILABLE:
            print_error(
                "Scapy is not installed. Install it with:\n"
                "    pip install -r requirements.txt\n"
                "or:\n"
                "    pip install scapy"
            )
            return False
        return True

    @staticmethod
    def list_interfaces():
        """
        Print all available network interfaces detected by Scapy.

        Returns:
            A list of interface name strings, or an empty list on failure.
        """
        if not NetworkSniffer.check_scapy_available():
            return []

        try:
            interfaces = get_if_list()
            if not interfaces:
                print_warning("No network interfaces were detected.")
                return []

            print_divider()
            print_info("Available Network Interfaces:")
            for idx, iface in enumerate(interfaces, start=1):
                print(f"  {idx}. {iface}")
            print_divider()
            return interfaces

        except Exception as exc:
            print_error(f"Failed to list network interfaces: {exc}")
            print_info(
                "On Windows, ensure Npcap is installed "
                "(https://npcap.com) and that you are running as Administrator."
            )
            return []

    # ----------------------------------------------------------------
    # Packet handling callback
    # ----------------------------------------------------------------

    def _handle_packet(self, packet):
        """
        Internal callback invoked by Scapy for every captured packet.
        Analyzes, filters, displays, and records the packet.
        """
        with self._lock:
            self._packet_counter += 1
            info = analyze_packet(packet, self._packet_counter)

            # Apply post-capture filtering. This keeps frontend and CLI
            # behavior consistent even when a BPF expression is unavailable.
            if self.packet_filter.is_active() and not self.packet_filter.matches(info):
                self._packet_counter -= 1
                return

            self.statistics.record(info.protocol, info.length)
            self.captured_packets.append(packet)
            self.captured_infos.append(info)

            # Keep the CLI's live display behavior. The Streamlit frontend
            # reads captured_infos directly and does not depend on stdout.
            print_divider()
            print(info.to_display_string(show_payload=self.payload_inspection_enabled))

    # ----------------------------------------------------------------
    # Capture operations
    # ----------------------------------------------------------------

    def capture(self, interface: str = None, packet_count: int = 0, timeout: int = None):
        """
        Start a packet capture session.

        Args:
            interface: Name of the interface to sniff on (None = default).
            packet_count: Number of packets to capture (0 = unlimited /
                          until Ctrl+C).
            timeout: Optional timeout in seconds to automatically stop
                     capture (None = no timeout).
        """
        if not NetworkSniffer.check_scapy_available():
            return

        bpf_filter = self.packet_filter.to_bpf_string()

        print_info(
            f"Starting capture on interface: {interface or 'default'} | "
            f"Count: {'unlimited (Ctrl+C to stop)' if packet_count == 0 else packet_count} | "
            f"{self.packet_filter.describe()}"
        )
        print_info(
            "Reminder: capture only on networks/systems you own or are "
            "explicitly authorized to monitor."
        )

        try:
            sniff(
                iface=interface,
                prn=self._handle_packet,
                count=packet_count,
                timeout=timeout,
                filter=bpf_filter,
                store=False,
            )
        except KeyboardInterrupt:
            print_warning("\nCapture stopped by user (Ctrl+C).")
        except PermissionError:
            print_error(
                "Permission denied. Packet capture requires elevated "
                "privileges.\n"
                "  - On Linux/macOS: run with 'sudo python3 main.py'\n"
                "  - On Windows: run your terminal 'as Administrator' and "
                "ensure Npcap is installed."
            )
        except OSError as exc:
            print_error(f"Operating system error during capture: {exc}")
            print_info(
                "This often means the selected interface is invalid or "
                "unavailable. Use option 4 to view available interfaces."
            )
        except Exception as exc:
            print_error(f"Unexpected error during capture: {exc}")
        else:
            if self._packet_counter == 0:
                print_warning("Capture ended with no packets matched/captured.")
            else:
                print_success(f"\nCapture complete. {self._packet_counter} packet(s) captured.")

    # ----------------------------------------------------------------
    # Non-blocking capture operations (used by the Streamlit frontend)
    # ----------------------------------------------------------------

    @property
    def is_capturing(self) -> bool:
        """Return whether a background capture session is currently active."""
        return bool(self._is_capturing)

    def start_background_capture(self, interface: str = None, packet_count: int = 0):
        """
        Start packet capture in the background using Scapy's AsyncSniffer.

        This method is intentionally separate from capture(), so the original
        blocking CLI behavior remains unchanged.
        """
        if not NetworkSniffer.check_scapy_available():
            raise RuntimeError("Scapy is not available.")

        if self._is_capturing:
            raise RuntimeError("A packet capture is already running.")

        bpf_filter = self.packet_filter.to_bpf_string()
        kwargs = {
            "iface": interface,
            "prn": self._handle_packet,
            "store": False,
        }
        if packet_count and int(packet_count) > 0:
            kwargs["count"] = int(packet_count)
        if bpf_filter:
            kwargs["filter"] = bpf_filter

        try:
            self._async_sniffer = AsyncSniffer(**kwargs)
            self._async_sniffer.start()
            self._is_capturing = True
            return True
        except Exception as exc:
            self._async_sniffer = None
            self._is_capturing = False
            raise RuntimeError(str(exc)) from exc

    def stop_background_capture(self):
        """Stop the active background capture safely."""
        if not self._async_sniffer:
            self._is_capturing = False
            return False

        try:
            if self._async_sniffer.running:
                self._async_sniffer.stop()
            return True
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc
        finally:
            self._async_sniffer = None
            self._is_capturing = False

    def snapshot(self):
        """
        Return thread-safe snapshots for a frontend without exposing mutable
        internal lists directly.
        """
        with self._lock:
            return list(self.captured_infos), {
                "total_packets": self.statistics.total_packets,
                "tcp_count": self.statistics.tcp_count,
                "udp_count": self.statistics.udp_count,
                "icmp_count": self.statistics.icmp_count,
                "arp_count": self.statistics.arp_count,
                "other_count": self.statistics.other_count,
                "total_bytes": self.statistics.total_bytes,
            }

    # ----------------------------------------------------------------
    # PCAP export
    # ----------------------------------------------------------------

    def save_to_pcap(self, filename: str = None) -> str:
        """
        Save all currently captured packets to a .pcap file inside the
        captures/ directory (created automatically if missing).

        Args:
            filename: Optional custom filename (without directory). If
                      None, a timestamped default name is generated.

        Returns:
            The full path to the saved file, or an empty string on failure.
        """
        if not self.captured_packets:
            print_warning("No packets have been captured yet. Nothing to save.")
            return ""

        ensure_directory(CAPTURES_DIR)

        if not filename:
            filename = f"capture_{get_filename_timestamp()}.pcap"
        elif not filename.lower().endswith(".pcap"):
            filename += ".pcap"

        full_path = f"{CAPTURES_DIR}/{filename}"

        try:
            wrpcap(full_path, self.captured_packets)
            print_success(f"Capture saved successfully to: {full_path}")
            print_info("Open this file with Wireshark for deeper analysis.")
            return full_path
        except PermissionError:
            print_error(f"Permission denied while writing to {full_path}.")
        except OSError as exc:
            print_error(f"Failed to write PCAP file: {exc}")
        except Exception as exc:
            print_error(f"Unexpected error while saving PCAP file: {exc}")

        return ""

    # ----------------------------------------------------------------
    # Misc
    # ----------------------------------------------------------------

    def reset_session(self):
        """Clear captured packets, analyzed info, and statistics."""
        self.captured_packets.clear()
        self.captured_infos.clear()
        self.statistics.reset()
        self._packet_counter = 0
        print_success("Capture session data cleared.")
