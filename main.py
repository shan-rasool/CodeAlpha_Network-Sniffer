#!/usr/bin/env python3
"""
main.py
-------
Entry point for the Basic Network Sniffer project.

A command-line, menu-driven network packet sniffer and analyzer built
with Python and Scapy. Captures live traffic, analyzes protocol details,
tracks statistics, supports optional filtering, and can export captures
to standard .pcap files (openable in Wireshark).

===========================================================================
 LEGAL & ETHICAL DISCLAIMER
===========================================================================
This project is intended ONLY for educational purposes and authorized
network monitoring - for example, your own computer, a lab environment,
or a network where you have obtained explicit permission to monitor
traffic. Do NOT capture or inspect traffic on networks or systems without
explicit permission. Unauthorized packet capture may violate local laws
and organizational policies.
===========================================================================

Author: CodeAlpha Internship Project (Cyber Security Track)
"""

import sys

from src.sniffer import NetworkSniffer
from src.filters import configure_filter_interactively
from src.utils import (
    print_banner,
    print_menu,
    print_divider,
    print_error,
    print_success,
    print_info,
    print_warning,
    prompt_int,
)

DISCLAIMER = (
    "This project is intended only for educational purposes and authorized\n"
    "network monitoring. Do not capture or inspect traffic on networks or\n"
    "systems without explicit permission."
)


def print_disclaimer():
    print_divider("=")
    print("  DISCLAIMER")
    print_divider("=")
    print(DISCLAIMER)
    print_divider("=")
    print()


def handle_start_live_capture(sniffer: NetworkSniffer):
    """Menu option 1: capture continuously until the user stops it."""
    interface = input("Enter interface name (leave blank for default): ").strip() or None
    print_info("Starting continuous capture. Press Ctrl+C to stop.")
    sniffer.capture(interface=interface, packet_count=0)
    print(sniffer.statistics.summary())


def handle_capture_specific_count(sniffer: NetworkSniffer):
    """Menu option 2: capture a specific number of packets."""
    interface = input("Enter interface name (leave blank for default): ").strip() or None
    count = prompt_int("Number of packets to capture: ", default=10, minimum=1)
    sniffer.capture(interface=interface, packet_count=count)
    print(sniffer.statistics.summary())


def handle_configure_filter(sniffer: NetworkSniffer):
    """Menu option 3: configure packet filter interactively."""
    sniffer.packet_filter = configure_filter_interactively(sniffer.packet_filter)


def handle_view_interfaces(sniffer: NetworkSniffer):
    """Menu option 4: list available network interfaces."""
    NetworkSniffer.list_interfaces()


def handle_toggle_payload_inspection(sniffer: NetworkSniffer):
    """Menu option 5: enable or disable payload inspection display."""
    sniffer.payload_inspection_enabled = not sniffer.payload_inspection_enabled
    state = "ENABLED" if sniffer.payload_inspection_enabled else "DISABLED"
    print_success(f"Payload inspection is now {state}.")
    if sniffer.payload_inspection_enabled:
        print_info(
            "Payload previews are limited in length and shown as readable "
            "text only. Encrypted traffic will be clearly marked as such "
            "and will not be decrypted."
        )


def handle_save_pcap(sniffer: NetworkSniffer):
    """Menu option 6: save the current capture session to a .pcap file."""
    filename = input(
        "Enter filename (leave blank for auto-generated timestamped name): "
    ).strip() or None
    sniffer.save_to_pcap(filename)


def handle_view_statistics(sniffer: NetworkSniffer):
    """Menu option 7: display current session statistics."""
    print(sniffer.statistics.summary())


def main():
    """Main interactive loop for the Basic Network Sniffer application."""
    print_banner()
    print_disclaimer()

    if not NetworkSniffer.check_scapy_available():
        print_error("Cannot continue without Scapy installed. Exiting.")
        sys.exit(1)

    sniffer = NetworkSniffer()

    menu_actions = {
        "1": handle_start_live_capture,
        "2": handle_capture_specific_count,
        "3": handle_configure_filter,
        "4": handle_view_interfaces,
        "5": handle_toggle_payload_inspection,
        "6": handle_save_pcap,
        "7": handle_view_statistics,
    }

    while True:
        print_menu()
        choice = input("Enter your choice: ").strip()

        if choice == "8":
            print_success("Exiting Basic Network Sniffer. Stay ethical, stay legal!")
            break

        action = menu_actions.get(choice)
        if action is None:
            print_error("Invalid choice. Please select an option between 1 and 8.")
            continue

        try:
            action(sniffer)
        except KeyboardInterrupt:
            print_warning("\nOperation interrupted by user.")
        except Exception as exc:
            print_error(f"An unexpected error occurred: {exc}")

        print()  # spacing before next menu render


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nProgram interrupted by user. Goodbye!")
        sys.exit(0)
