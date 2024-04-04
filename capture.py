from scapy.all import sniff, TCP, IP, get_if_list
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def list_interfaces():
    """
    List all network interfaces available on the system.
    """
    interfaces = get_if_list()
    logging.info("Available network interfaces:")
    for idx, interface in enumerate(interfaces):
        print(f"{idx + 1}: {interface}")
    return interfaces

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

def capture_tcp_packets(interface, duration, store=False):
    """
    Captures TCP packets on the specified network interface for the specified duration.

    Parameters:
    - interface (str): The network interface to listen on.
    - duration (int): Duration in seconds for the packet capture.
    - store (bool): Whether to store captured packets in memory.
    """
    try:
        logging.info(f"Starting TCP packet capture on {interface} for {duration} seconds...")
        sniff(iface=interface, timeout=duration, filter="tcp", prn=packet_callback, store=store)
        logging.info("Packet capture completed.")
    except PermissionError:
        logging.error("Permission denied. Try running as root or administrator.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    interfaces = list_interfaces()
    choice = int(input("Select the interface to capture from (enter the number): ")) - 1
    if choice < 0 or choice >= len(interfaces):
        logging.error("Invalid interface selection.")
    else:
        selected_interface = interfaces[choice]
        duration = int(input("Enter the duration of capture in seconds: "))
        capture_tcp_packets(selected_interface, duration, store=False)
