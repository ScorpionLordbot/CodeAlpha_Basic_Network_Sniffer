import socket
import struct

def ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return dest_mac, src_mac, socket.htons(proto)

def ip_header(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! B B 2x 4s 4s', data[12:20])
    return version, header_length, ttl, proto, socket.inet_ntoa(src), socket.inet_ntoa(target)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SIO_RCVALL, 1)
    s.bind(('', 0))  # Listen on all interfaces

    while True:
        packet = s.recvfrom(65535)[0]
        eth_header = ethernet_header(packet)
        if eth_header[2] == 8:  # IP Protocol
            ip_header = ip_header(packet[14:])
            print(f'IP Header: {ip_header}')
        else:
            print(f'Ethernet Header: {eth_header}')

if __name__ == '__main__':
    main()