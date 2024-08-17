import scapy.all as scapy

def sniff_packets(interface):
  scapy.sniff(iface=interface, store=False, prn=lambda x: x.summary())

if __name__ == "__main__":
  interface = "your_interface"  # Replace with your network interface
  sniff_packets(interface)