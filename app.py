"""
Streamlit frontend for the Basic Network Sniffer.

Run:
    streamlit run app.py

Use only on systems and networks you own or are explicitly authorized
to monitor.
"""

import os
import time

import streamlit as st

from src.filters import PacketFilter
from src.sniffer import NetworkSniffer
from src.utils import format_bytes, is_valid_ipv4, is_valid_port


st.set_page_config(
    page_title="Basic Network Sniffer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def init_state():
    if "sniffer" not in st.session_state:
        st.session_state.sniffer = NetworkSniffer()
    if "interfaces" not in st.session_state:
        st.session_state.interfaces = []
    if "selected_packet" not in st.session_state:
        st.session_state.selected_packet = 0


def refresh_interfaces():
    if not NetworkSniffer.check_scapy_available():
        st.session_state.interfaces = []
        return []
    try:
        from scapy.all import get_if_list
        st.session_state.interfaces = get_if_list()
    except Exception:
        st.session_state.interfaces = []
    return st.session_state.interfaces


def packet_rows(infos):
    rows = []
    for info in infos:
        rows.append({
            "Packet #": info.packet_number,
            "Timestamp": info.timestamp,
            "Protocol": info.protocol,
            "Source IP": info.src_ip or "-",
            "Destination IP": info.dst_ip or "-",
            "Source Port": info.src_port if info.src_port is not None else "-",
            "Destination Port": info.dst_port if info.dst_port is not None else "-",
            "Length": info.length,
            "TCP Flags": info.tcp_flags or "-",
        })
    return rows


def current_filter_from_sidebar():
    protocol = st.session_state.protocol_filter
    source_ip = st.session_state.source_filter.strip()
    destination_ip = st.session_state.destination_filter.strip()
    port_text = st.session_state.port_filter.strip()

    errors = []
    if source_ip and not is_valid_ipv4(source_ip):
        errors.append("Source IP must be a valid IPv4 address.")
    if destination_ip and not is_valid_ipv4(destination_ip):
        errors.append("Destination IP must be a valid IPv4 address.")
    if port_text and not is_valid_port(port_text):
        errors.append("Port must be between 0 and 65535.")

    if errors:
        return None, errors

    return PacketFilter(
        protocol=None if protocol == "All" else protocol,
        source_ip=source_ip or None,
        destination_ip=destination_ip or None,
        port=int(port_text) if port_text else None,
    ), []


init_state()
sniffer = st.session_state.sniffer

st.title("🛡️ Basic Network Sniffer")
st.caption("Real-Time Network Traffic Monitoring and Packet Analysis")
st.warning(
    "Authorized use only: capture traffic only on systems and networks you own "
    "or are explicitly authorized to monitor."
)

with st.sidebar:
    st.header("Capture Controls")

    if st.button("🔄 Refresh Interfaces", use_container_width=True):
        refresh_interfaces()

    if not st.session_state.interfaces:
        refresh_interfaces()

    interface_options = ["Default interface"] + st.session_state.interfaces
    selected_interface = st.selectbox("Network Interface", interface_options)

    capture_mode = st.radio(
        "Capture Mode",
        ["Continuous", "Specific packet count"],
        horizontal=True,
    )

    packet_count = 0
    if capture_mode == "Specific packet count":
        packet_count = st.number_input(
            "Number of packets",
            min_value=1,
            max_value=100000,
            value=10,
            step=1,
        )

    st.divider()
    st.subheader("Packet Filter")
    st.selectbox(
        "Protocol",
        ["All", "TCP", "UDP", "ICMP", "ARP"],
        key="protocol_filter",
    )
    st.text_input("Source IP", placeholder="Optional, e.g. 192.168.1.10", key="source_filter")
    st.text_input("Destination IP", placeholder="Optional", key="destination_filter")
    st.text_input("Port", placeholder="Optional, 0-65535", key="port_filter")

    apply_filter = st.button("Apply Filter", use_container_width=True)
    clear_filter = st.button("Clear Filter", use_container_width=True)

    if apply_filter:
        new_filter, errors = current_filter_from_sidebar()
        if errors:
            for error in errors:
                st.error(error)
        else:
            sniffer.packet_filter = new_filter
            st.success("Filter applied.")

    if clear_filter:
        sniffer.packet_filter = PacketFilter()
        st.session_state.protocol_filter = "All"
        st.session_state.source_filter = ""
        st.session_state.destination_filter = ""
        st.session_state.port_filter = ""
        st.success("Filter cleared.")

    st.divider()
    sniffer.payload_inspection_enabled = st.checkbox(
        "Enable Payload Inspection",
        value=sniffer.payload_inspection_enabled,
    )

    st.divider()
    if st.button("🗑️ Clear Session Data", use_container_width=True):
        if sniffer.is_capturing:
            st.error("Stop packet capture before clearing the session.")
        else:
            sniffer.reset_session()
            st.session_state.selected_packet = 0
            st.success("Session data cleared.")

left, right = st.columns([1, 2])

with left:
    status = "🟢 Capturing" if sniffer.is_capturing else "⚪ Ready / Stopped"
    st.subheader("Status")
    st.info(status)

    start_disabled = sniffer.is_capturing
    stop_disabled = not sniffer.is_capturing

    if st.button("▶️ Start Capture", disabled=start_disabled, use_container_width=True):
        selected = None if selected_interface == "Default interface" else selected_interface
        try:
            sniffer.start_background_capture(
                interface=selected,
                packet_count=int(packet_count),
            )
            st.success("Packet capture started.")
        except Exception as exc:
            st.error(
                "Unable to start packet capture. On Windows, verify that Npcap "
                f"is installed and run the terminal as Administrator. Details: {exc}"
            )

    if st.button("⏹️ Stop Capture", disabled=stop_disabled, use_container_width=True):
        try:
            sniffer.stop_background_capture()
            st.success("Packet capture stopped.")
        except Exception as exc:
            st.error(f"Unable to stop packet capture cleanly: {exc}")

    st.caption(f"Active filter: {sniffer.packet_filter.describe()}")

with right:
    st.subheader("Capture Actions")
    infos, stats = sniffer.snapshot()
    if st.button("💾 Export Capture to PCAP", use_container_width=True):
        if not infos:
            st.warning("No packets have been captured yet.")
        else:
            path = sniffer.save_to_pcap()
            if path and os.path.exists(path):
                st.success(f"Saved: {path}")

    infos, stats = sniffer.snapshot()
    if infos:
        latest_path = None
        captures_dir = "captures"
        if os.path.isdir(captures_dir):
            pcaps = [
                os.path.join(captures_dir, name)
                for name in os.listdir(captures_dir)
                if name.lower().endswith(".pcap")
            ]
            if pcaps:
                latest_path = max(pcaps, key=os.path.getmtime)
        if latest_path:
            with open(latest_path, "rb") as f:
                st.download_button(
                    "⬇️ Download Latest PCAP",
                    data=f.read(),
                    file_name=os.path.basename(latest_path),
                    mime="application/vnd.tcpdump.pcap",
                    use_container_width=True,
                )

st.divider()
infos, stats = sniffer.snapshot()

st.subheader("Live Statistics")
m1, m2, m3, m4, m5, m6, m7 = st.columns(7)
m1.metric("Total", stats["total_packets"])
m2.metric("TCP", stats["tcp_count"])
m3.metric("UDP", stats["udp_count"])
m4.metric("ICMP", stats["icmp_count"])
m5.metric("ARP", stats["arp_count"])
m6.metric("Other", stats["other_count"])
m7.metric("Data", format_bytes(stats["total_bytes"]))

st.divider()
st.subheader("Captured Packets")

if infos:
    st.dataframe(
        packet_rows(infos),
        use_container_width=True,
        hide_index=True,
        height=420,
    )

    packet_numbers = [info.packet_number for info in infos]
    selected_number = st.selectbox(
        "Select a packet for detailed analysis",
        packet_numbers,
        index=max(0, min(len(packet_numbers) - 1, st.session_state.selected_packet)),
    )
    st.session_state.selected_packet = packet_numbers.index(selected_number)
    selected_info = next(info for info in infos if info.packet_number == selected_number)

    with st.expander(f"Packet #{selected_info.packet_number} Details", expanded=True):
        d1, d2 = st.columns(2)
        with d1:
            st.write("**Timestamp:**", selected_info.timestamp)
            st.write("**Protocol:**", selected_info.protocol)
            st.write("**Length:**", f"{selected_info.length} bytes")
            st.write("**Source IP:**", selected_info.src_ip or "-")
            st.write("**Source Port:**", selected_info.src_port if selected_info.src_port is not None else "-")
        with d2:
            st.write("**Destination IP:**", selected_info.dst_ip or "-")
            st.write("**Destination Port:**", selected_info.dst_port if selected_info.dst_port is not None else "-")
            st.write("**TCP Flags:**", selected_info.tcp_flags or "-")
            st.write("**ICMP Type:**", selected_info.icmp_type or "-")
            st.write("**ICMP Code:**", selected_info.icmp_code or "-")

        if sniffer.payload_inspection_enabled:
            st.markdown("**Payload Preview**")
            st.code(selected_info.payload_preview or "<no payload data available>")
else:
    st.info("No packets captured yet. Select an interface and start an authorized capture.")

# A lightweight refresh loop while a background capture is active.
if sniffer.is_capturing:
    time.sleep(1)
    st.rerun()
