from scapy.all import sniff, TCP, IP
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    This function extracts and logs TCP packet details.
    """
    if packet.haslayer(TCP):
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

def capture_tcp_packets(interface='eth0', count=0, store=False):
    """
    Captures TCP packets on the specified network interface.
    Uses a callback function to process each packet.

    Parameters:
    - interface (str): The network interface to listen on (default 'eth0').
    - count (int): The number of packets to capture (0 for unlimited).
    - store (bool): Whether to store captured packets in memory.
    """
    try:
        logging.info("Starting TCP packet capture...")
        sniff(iface=interface, count=count, filter="tcp", prn=packet_callback, store=store)
    except PermissionError:
        logging.error("Permission denied. Try running as root or administrator.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    # Example usage: Capture TCP packets indefinitely
    capture_tcp_packets(interface="en0", count=0, store=False)
