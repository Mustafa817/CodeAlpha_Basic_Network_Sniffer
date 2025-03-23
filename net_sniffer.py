from scapy.all import sniff, Ether, IP, TCP, UDP

def packet_handler(packet):
    # Check if the packet is an Ethernet frame
    if Ether in packet:
        print("Ethernet Frame:")
        
        print(f"Source MAC Address: {packet[Ether].src}, Destination MAC Address: {packet[Ether].dst}")

    # Check if the packet is an IP packet
    if IP in packet:
        print("IP Packet:")
        
        print(f"Source IP Address: {packet[IP].src}, Destination IP Address: {packet[IP].dst}")

    # Check if the packet is a TCP segment
    if TCP in packet:
        print("TCP Segment:")
        
        print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")

    # Check if the packet is a UDP datagram
    if UDP in packet:
        print("UDP Datagram:")
        
        print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")

def start_sniffer():
    print("Starting network sniffer...")
    print("This program will capture and display detailed information about network packets.")
    print("Press Ctrl+C to stop the sniffer.")
    # Start sniffing packets and call packet_handler for each captured packet
    sniff(prn=packet_handler, store=0)

if __name__ == "__main__":
    start_sniffer()