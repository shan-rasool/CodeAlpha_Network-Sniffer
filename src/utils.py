"""
utils.py
--------
General-purpose helper functions used across the Basic Network Sniffer
project: terminal banners, timestamp formatting, safe payload rendering,
input validation helpers, and directory management.

Author: CodeAlpha Internship Project
"""

import os
import re
import string
from datetime import datetime


# --------------------------------------------------------------------------
# Display helpers
# --------------------------------------------------------------------------

def print_banner():
    """Print the main application banner / menu header."""
    banner = r"""
=========================================
       BASIC NETWORK SNIFFER
=========================================
"""
    print(banner)


def print_menu():
    """Print the main interactive menu and return nothing (UI only)."""
    menu = """
1. Start Live Packet Capture
2. Capture Specific Number of Packets
3. Configure Packet Filter
4. View Available Network Interfaces
5. Enable/Disable Payload Inspection
6. Save Capture to PCAP
7. View Statistics
8. Exit
"""
    print(menu)


def print_divider(char="-", length=60):
    """Print a simple divider line for readability in terminal output."""
    print(char * length)


def print_error(message: str):
    """Print a clearly-marked, user-friendly error message."""
    print(f"[ERROR] {message}")


def print_warning(message: str):
    """Print a clearly-marked warning message."""
    print(f"[WARNING] {message}")


def print_success(message: str):
    """Print a clearly-marked success message."""
    print(f"[OK] {message}")


def print_info(message: str):
    """Print a clearly-marked informational message."""
    print(f"[INFO] {message}")


# --------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------

def get_current_timestamp() -> str:
    """Return a human-readable timestamp for on-screen packet display."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def get_filename_timestamp() -> str:
    """Return a filesystem-safe timestamp suitable for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_payload_preview(raw_bytes: bytes, max_length: int = 64) -> str:
    """
    Convert raw payload bytes into a safe, printable string for terminal
    display. Non-printable bytes are rendered as '.' so the output never
    corrupts the terminal or attempts to interpret/decrypt data.

    Args:
        raw_bytes: The raw payload bytes extracted from a packet.
        max_length: Maximum number of bytes to preview.

    Returns:
        A printable string representation of the payload, truncated and
        annotated if it was cut short.
    """
    if not raw_bytes:
        return "<no payload data available>"

    truncated = len(raw_bytes) > max_length
    chunk = raw_bytes[:max_length]

    printable = set(bytes(string.printable, "ascii"))
    rendered = "".join(
        chr(b) if b in printable and chr(b) not in "\r\n\t" else "."
        for b in chunk
    )

    suffix = f" ... [truncated, {len(raw_bytes)} bytes total]" if truncated else ""
    return f"{rendered}{suffix}"


def format_bytes(num_bytes: int) -> str:
    """Format a byte count into a human-readable string (B, KB, MB)."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f} KB"
    else:
        return f"{num_bytes / (1024 * 1024):.2f} MB"


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

IPV4_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


def is_valid_ipv4(ip_str: str) -> bool:
    """
    Validate that a string is a well-formed IPv4 address.

    Args:
        ip_str: The string to validate.

    Returns:
        True if valid IPv4 address, False otherwise.
    """
    match = IPV4_PATTERN.match(ip_str.strip())
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def is_valid_port(port_str: str) -> bool:
    """
    Validate that a string represents a valid TCP/UDP port number.

    Args:
        port_str: The string to validate.

    Returns:
        True if valid port (0-65535), False otherwise.
    """
    if not port_str.strip().isdigit():
        return False
    return 0 <= int(port_str.strip()) <= 65535


def is_valid_protocol(protocol_str: str) -> bool:
    """Validate that a protocol filter string is one we support."""
    return protocol_str.strip().upper() in {"TCP", "UDP", "ICMP", "ARP"}


def prompt_int(prompt_text: str, default=None, minimum=1, maximum=None):
    """
    Prompt the user for an integer with validation and a sensible default.

    Args:
        prompt_text: Text shown to the user.
        default: Value returned if the user presses Enter with no input.
        minimum: Minimum acceptable value.
        maximum: Maximum acceptable value (None = no upper bound).

    Returns:
        A validated integer, or the default value.
    """
    while True:
        raw = input(prompt_text).strip()
        if raw == "" and default is not None:
            return default
        if not raw.lstrip("-").isdigit():
            print_error("Please enter a valid whole number.")
            continue
        value = int(raw)
        if value < minimum or (maximum is not None and value > maximum):
            print_error(f"Please enter a number between {minimum} and {maximum}.")
            continue
        return value


# --------------------------------------------------------------------------
# Filesystem helpers
# --------------------------------------------------------------------------

def ensure_directory(path: str):
    """Create a directory (and parents) if it does not already exist."""
    os.makedirs(path, exist_ok=True)
