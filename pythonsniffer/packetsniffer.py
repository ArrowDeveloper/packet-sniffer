from utilities import *

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

active_ifaces = get_active_interface()

if not active_ifaces:
    print("No active network interface")
    exit(1)
target_iface = active_ifaces[0].strip('\x00')

sock.bind((target_iface, 0))

print(f"PACKET SNIFFER RUNNING AT {target_iface}...")

while True:
    raw_bytes, addr = sock.recvfrom(65535)
    headers = raw_bytes[:14]
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', headers) #6s for 6 bytes

    if proto == 0x0800: #Only accepting IPv4

        ip_data = raw_bytes[14:]
        version_ihl, tos, total_len, idfication, flags_fragment, ttl, ip_proto,check_sum, src_ip, dst_ip = struct.unpack("!BBHHHBBH4s4s", ip_data[:20])

        version = version_ihl >> 4  
        ihl = version_ihl & 0x0F 
        ip_header_len = ihl * 4

        transport_data = ip_data[ip_header_len:]

        src_ip_readeable = socket.inet_ntoa(src_ip)
        dst_ip_readeable = socket.inet_ntoa(dst_ip)

        if ip_proto == 17 and len(transport_data) >= 8: #Getting UDP

            src_port, dst_port, udp_len, udp_checksum = struct.unpack("!HHHH", transport_data[:8]) #First 8 bytes is the header
            
            udp_payload = transport_data[8:] 

            service = UDP_SERVICES.get(src_port) or UDP_SERVICES.get(dst_port) or "UNKNOWN"

            if service == "DNS" and len(udp_payload) >= 12:
                dns_id, dns_flags, qdcount, anscount, nscount, arcount = struct.unpack("!HHHHHH", udp_payload[:12])
                
                is_response = dns_flags & 0x8000 

                offset = 12 # To get to first byte
                labels = []
                
                while True: # Getting the domain from the payload
                    dns_length = udp_payload[offset]

                    if dns_length == 0:
                        break

                    label = udp_payload[offset + 1 : offset + dns_length + 1].decode() 
                    labels.append(label)

                    offset += 1 + dns_length
                
                offset += 1
                qtype, qclass = struct.unpack("!HH", udp_payload[offset:offset+4]) #Query payload

                domain = ".".join(labels)

                qtype_text = DNS_TYPES.get(qtype, str(qtype))

                offset += 4
                
                if qclass == 1:
                    qclass_text = "IN"
                else:
                    qclass_text = str(qclass)

                if anscount > 0:
                    if udp_payload[offset] & 0xC0 == 0xC0:

                        offset += 2
                        atype, aclass, ttl,rdlength = struct.unpack("!HHIH", udp_payload[offset:offset+10])
                        offset += 10
                        print("RDLENGTH:",rdlength)
                        rdata = udp_payload[offset: offset+rdlength]

                        if atype == 1 and rdlength == 4:
                            ipv4addr = ".".join(map(str, rdata))
                            print("ANSWER IPV4", "TYPE:", atype, "CLASS:", aclass, "TTL:", ttl, "IP:", ipv4addr)

                        elif atype == 28 and rdlength == 16:
                            groups = []
                            for i in range(0,16,2):
                                group = rdata[i:i+2]
                                groups.append(group.hex())
                    
                            ipv6addr = ipaddress.IPv6Address(":".join(groups))
                            
                            print("ANSWER IPV6", "TYPE:", atype, "CLASS:", aclass, "TTL:", ttl, "IP:", ipv6addr)
                        else:
                            print("ANSWER", "TYPE:", atype, "CLASS:", aclass, "TTL:", ttl, "RDATA", rdata)


        
                if is_response:
                    print("RESPONSE","ID:", dns_id, domain, qtype_text, qclass_text)
                else:
                    print("QUERY", "ID:", dns_id, domain, qtype_text, qclass_text)

                #print(src_ip_readeable, "->", dst_ip_readeable, src_port, "->", dst_port, service)


#        if ip_proto == 1 and len(transport_data) >= 4:

#            icmp_type, icmp_code, icmp_checksum = struct.unpack("!BBH", transport_data[:4])

#            print(src_ip_readeable, dst_ip_readeable, format_icmp(icmp_type), icmp_code)

        if ip_proto == 6 and len(transport_data) >= 20:
            src_port, dst_port, seq, ack, offset_reserved_flags, window, tcp_checksum, urg_ptr = struct.unpack('!HHLLHHHH', transport_data[:20])
            
            flags = []

            tcp_offset = (offset_reserved_flags >> 12) * 4

            
            tcp_payload = transport_data[tcp_offset:]

            urg_flag = (offset_reserved_flags & 32) >> 5
            ack_flag = (offset_reserved_flags & 16) >> 4
            psh_flag = (offset_reserved_flags & 8) >> 3
            rst_flag = (offset_reserved_flags & 4) >> 2
            syn_flag = (offset_reserved_flags & 2) >> 1
            fin_flag = offset_reserved_flags & 1

            if syn_flag:
                flags.append("SYN")
            if ack_flag:
                flags.append("ACK")
            if fin_flag:
                flags.append("FIN")
            if rst_flag:
                flags.append("RST")
            if psh_flag:
                flags.append("PSH")
            if urg_flag:
                flags.append("URG")

            service = TCP_SERVICES.get(src_port) or TCP_SERVICES.get(dst_port) or "UNKNOWN"
            preview = tcp_payload[:30]
            first3 = tcp_payload[:3]

            if len(tcp_payload) > 0:

                if first3[:2] in (b'\x16\x03', b'\x17\x03', b'\x14\x03'):
                    print("Likely TLS traffic")

                elif any(preview.startswith(prefix) for prefix in HTTP_PREFIXES):

                    print("HTTP", repr(preview.decode(errors='ignore')))

                elif preview.startswith(b'SSH-'):

                    print("SSH", repr(preview.decode(errors='ignore')))

                else: 
                    payload_text = tcp_payload[:64].decode(errors='ignore')

                    if is_readable(payload_text):

                        print("TEXT", repr(payload_text))
                        
                    else:

                        print("HEX", preview.hex())

            #print(src_ip_readeable, "->", dst_ip_readeable, src_port, "->", dst_port, flags, service, "Payload len: ", len(tcp_payload))
