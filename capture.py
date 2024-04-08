from scapy.all import sniff, TCP, IP, get_if_list, wrpcap, get_if_addr
import logging
import time
import subprocess
import speedtest

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def list_active_interfaces():
    """
    List all active network interfaces on the system.
    """
    active_interfaces = []
    for interface in get_if_list():
        try:
            if_addr = get_if_addr(interface)
            if if_addr != '0.0.0.0': # Check if interface has non-default IPv4 address (To remove disabled or VPN interfaces from the list)
                active_interfaces.append((interface, if_addr))
        except ValueError as e:
            # Will trigger if interface has no IPv4 address
            continue
    return active_interfaces

def perform_speedtest():
    """
    Perform internet speedtest and logs the results
    """

    logging.info("Testing internet speed...")
    st = speedtest.Speedtest()
    st.get_servers()
    best = st.get_best_server()
    st.download
    st.upload
    ping_result = st.results.ping
    download_speed = st.download() / 1000000 # In Mbps
    upload_speed = st.upload() / 1000000 # In Mbps

    logging.info(f"Speed Test Results: Ping: {ping_result} ms, Download: {download_speed:.2f} Mbps, Upload: {upload_speed:.2f} Mbps")

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    This function extracts and logs TCP packet details.
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):
        # Extracting basic details from the packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        seq_num = packet[TCP].seq
        ack_num = packet[TCP].ack
        tcp_flags = packet[TCP].flags

        # Logging the TCP packet details
        logging.info(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Seq: {seq_num} | Ack: {ack_num} | Flags: {tcp_flags}")

def capture_tcp_packets(selected_interface, duration, filename):
    """
    Captures TCP packets on the specified network interface for the specified duration.

    Parameters:
    - interface (str): The network interface to listen on.
    - duration (int): Duration in seconds for the packet capture.
    - filename (str): The name of the file to save the captured packets.
    """
    try:
        logging.info(f"Starting TCP packet capture on {interface} for {duration} seconds...")
        packets = sniff(iface=interface, timeout=duration, filter="tcp", prn=packet_callback, store=True)
        logging.info(f"Packet capture completed. Saving {len(packets)} packets to {filename}")
        wrpcap(filename, packets)
    except PermissionError:
        logging.error("Permission denied. Try running as root or administrator.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    interfaces = list_active_interfaces()
    if interfaces:
        logging.info("Active network interfaces:")
        for idx, (interface, ip) in enumerate(interfaces):
            logging.info(f"{idx + 1}: {interface} (IP: {ip})")
    choice = int(input("Select the interface to capture from (enter the number): ")) - 1
    if choice < 0 or choice >= len(interfaces):
        logging.error("Invalid interface selection.")
    else:
        selected_interface, selected_ip = interfaces[choice]
        duration = int(input("Enter the duration of capture in seconds: "))
        filename = input("Enter the filename to save captured packets (e.g. - capture.pcap): ")
        capture_tcp_packets(selected_interface, duration, filename)
    perform_speedtest() #Not for selected interfaces
