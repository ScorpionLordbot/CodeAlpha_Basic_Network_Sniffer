import scapy.all as scapy

def sniff_packets(interface):
    def packet_handler(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            print(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}")
        else:
            print("Non-IP packet")

    scapy.sniff(iface=interface, store=False, prn=packet_handler)

if __name__ == "__main__":
    interface = "eth0"
    sniff_packets(interface)