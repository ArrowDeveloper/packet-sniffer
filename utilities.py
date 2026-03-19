import fcntl
import array
import socket
import struct

def get_active_interface():
    #Creating a Dummy socket to connect to
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 

    # Allocating the memory since linux kernel is C based, 4096 is plenty for all interfaces

    names = array.array('B', b'\0' * 4096)

    # SIOCGIFCONF = 0x8912 is a constant to get interface conf
    # Using struct to unpack the interface and put it in the buffer we allocated
    # [0] in the end cause struct output is tuple
    
    outbytes = struct.unpack("iL", fcntl.ioctl(s.fileno(), 0x8912, struct.pack("iL", 4096, names.buffer_info()[0])))[0]
    
    namestr = names.tobytes()
    ifaces = []
    # Each interface entry in 64bit sys is 40 bytes long in Linux system

    for i in range(0, outbytes, 40):
        name = namestr[i:i+16].split(b'\0', 1)[0].decode() # Decoding the buffer to get interface names
        if name != 'lo': 
            ifaces.append(name)

    return ifaces


UDP_SERVICES = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    123: "NTP",
    161: "SNMP",
    1900: "SSDP",
    5353: "mDNS"
}

TCP_SERVICES = {
    80 : "HTTP",
    8080 : "HTTP",
    22 : "SSH",
    23 : "Telnet",
    25 : "SMTP",
    53 :"DNS",
    3306 : "MySQL",
    20 : "FTP",
    21 : "FTP",
    443 : "HTTPS"
        }

DNS_TYPES = {
    1: "A",
    5: "CNAME",
    28: "AAAA"
}

HTTP_PREFIXES = [b'GET ',
    b'POST ', 
    b'HEAD ',
    b'PUT ',
    b'DELETE ',
    b'HTTP/']

def is_readable(s):
    if not s:
        return False

    printable = 0 
    for ch in s:
        if ch.isprintable() or ch in '\r\n\t':
            printable += 1
    return printable / len(s) > 0.7

def format_ethertype(protoc):
    if protoc == 0x0800:
        return "IPv4"
    elif protoc == 0x806:
        return "ARP"
    elif protoc == 0x86DD:
        return "IPv6"
    else:
        return hex(protoc)

def format_icmp(icmp_type):
    if icmp_type == 8:
        return "Echo Request"
    if icmp_type == 0:
        return "Echo Reply"
    if icmp_type == 3:
        return "Destination Unreachable"
    if icmp_type == 11:
        return "Time Exceeded"
    else:
        return str(icmp_type)

def format_mac(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def format_ip_proto(ip_proto):
    if ip_proto == 1:
        return "ICMP"
    elif ip_proto == 6:
        return "TCP"
    elif ip_proto == 17:
        return "UDP"
    else:
        return str(ip_proto)
