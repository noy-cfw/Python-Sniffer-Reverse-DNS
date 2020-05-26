import socket
import struct

def main():
    #Create an INET, raw socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # Loop receiving packets
    while True:
        raw_data, addr = conn.recvfrom(65535)
        version, header_length, ttl, proto, src, target, data = ipv4_packet(raw_data)
        protocol = checkprotocol(proto)
        totalleng = struct.unpack('! 1s 1s',raw_data[2:4])
        srcport, destport = checkport(raw_data[20:24])

        host = rDNS(addr[0])
        print(host)
 
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl , proto, ipv4(src), ipv4(target), data[header_length:]

# Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

def checkprotocol(proto):
    protocol = ''
    if proto == 17:
        protocol = 'UDP'
        return(protocol)
    elif proto == 6:
        protocol = 'TCP'
        return(protocol)
    else:
        protocol = '0'
        return(protocol)

def checkport(port):
    srcport, destport = struct.unpack('! H H', port)
    return srcport, destport

def checkudplength(udplength):
    udplength = struct.unpack('! H', udplength)
    return udplength

def rDNS(addr):
    try:
        host = socket.gethostbyaddr(addr)
        return host[0]
    except socket.herror:
        return addr
    else:
        return addr

main()