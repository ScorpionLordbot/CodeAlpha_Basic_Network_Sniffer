import scapy.all as scapy
from scapy.layers.inet import IP

def sniff_packets(interface):
    def packet_handler(packet):
        try:
            # Check for IP layer
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                print(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}")
            elif ARP in packet:
                # Handle ARP packets
                print("ARP packet")
            elif ICMP in packet:
                # Handle ICMP packets
                print("ICMP packet")
            else:
                print("Unknown packet type")
        except Exception as e:
            print(f"Error processing packet: {e}")
            packet.show()  # Print packet details for debugging

    scapy.sniff(iface=interface, store=False, prn=packet_handler)

if __name__ == "__main__":
    interface = "eth0"
    sniff_packets(interface)