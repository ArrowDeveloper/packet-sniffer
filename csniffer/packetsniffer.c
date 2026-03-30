#include "headers.h"

typedef struct{
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    uint16_t proto;
}headers; 

typedef struct{
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint8_t ip_proto;
    unsigned char src_ip[4];
    unsigned char dst_ip[4];
}ip_data;

typedef struct{
    uint16_t src_port;
    uint16_t dst_port;
}udppayload;

typedef struct{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_checksum;
}icmppayload;

typedef struct{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t offset_flags;
}tcppayload;

int main(){
    struct sockaddr *addr;

    headers head;

    struct sockaddr_storage localaddr;
    
    socklen_t addrsize = sizeof(localaddr);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(0x0003));

    if(sock == -1){
        perror("sock");
    }
    
    unsigned char buffer[65535];

    while(1){
        
        ssize_t bytes_received = 0;

        ip_data ipdata;

        bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&localaddr, &addrsize);
        
        memcpy(&head.dest_mac, buffer, sizeof(head.dest_mac));
        memcpy(&head.src_mac, buffer + 6, sizeof(head.src_mac));

        memcpy(&head.proto, buffer + 12, sizeof(head.proto));

        head.proto = ntohs(head.proto);

        //printf("Source: %x Destination: %x Proto: %x\n", head.src_mac, head.dest_mac, head.proto);

        if(head.proto == 0x0800){

            uint8_t version;
            uint8_t ihl;
            int ip_header_len;
            char src_ip_readable[INET_ADDRSTRLEN];
            char dst_ip_readable[INET_ADDRSTRLEN];
            
            memcpy(&ipdata.version_ihl, buffer + 14, sizeof(ipdata.version_ihl));
            memcpy(&ipdata.src_ip, buffer + 26, sizeof(ipdata.src_ip));
            memcpy(&ipdata.dst_ip, buffer + 30, sizeof(ipdata.dst_ip));
            memcpy(&ipdata.total_len, buffer + 16, sizeof(ipdata.total_len));
            memcpy(&ipdata.ip_proto, buffer + 23, sizeof(ipdata.ip_proto));

            ipdata.total_len = ntohs(ipdata.total_len);

            version = ipdata.version_ihl >>4;
            ihl = ipdata.version_ihl & 0x0F;
            ip_header_len = ihl * 4;

            inet_ntop(AF_INET, ipdata.src_ip, src_ip_readable, sizeof(src_ip_readable));
            inet_ntop(AF_INET, ipdata.dst_ip, dst_ip_readable, sizeof(dst_ip_readable));

            int offset = 14 + ip_header_len;
            
            if (ipdata.total_len < offset){
                continue;
            }

            size_t transport_length = ipdata.total_len - offset;

            unsigned char *transport_data = malloc(transport_length);

            if(transport_data == NULL){
                continue;
            }

            //printf("Transport Length: %d\n", transport_length);
            //printf("IP Proto: %d\n", ipdata.ip_proto);

            memcpy(transport_data, buffer + offset, transport_length);

            //printf("Transport Data: %p\n", (void*)transport_data);

            if(ipdata.ip_proto == 17 && transport_length >= 8){
                udppayload payload;

                memcpy(&payload.src_port, transport_data, sizeof(payload.src_port));
                memcpy(&payload.dst_port, transport_data + 2, sizeof(payload.dst_port));

                payload.src_port = ntohs(payload.src_port);
                payload.dst_port = ntohs(payload.dst_port);

               printf("Source IP: %s -> Destination IP: %s Source Port: %d - > Destination Port: %d\n", src_ip_readable, dst_ip_readable, payload.src_port, payload.dst_port);
            
            }

            if(ipdata.ip_proto == 1 && transport_length >= 4){
                icmppayload payload;

                memcpy(&payload.icmp_type, transport_data, sizeof(payload.icmp_type));
                memcpy(&payload.icmp_code, transport_data + 1 , sizeof(payload.icmp_code));

                payload.icmp_type = ntohs(payload.icmp_type);
                payload.icmp_code = ntohs(payload.icmp_code);

                printf("Source IP: %s -> Destination IP: %s ICMP type: %d ICMP code: ", src_ip_readable, dst_ip_readable, payload.icmp_type, payload.icmp_code);
                
            }


            if(ipdata.ip_proto == 6 && transport_length >= 20){
                tcppayload payload;
                uint16_t tcp_offset, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag;
                int count = 0;
                char *flags[64];
                const char* srcservice;
                const char* dstservice;

                memcpy(&payload.src_port, transport_data, sizeof(payload.src_port));
                memcpy(&payload.dst_port, transport_data + 2, sizeof(payload.dst_port));
                memcpy(&payload.offset_flags, transport_data + 10, sizeof(payload.offset_flags));

                payload.src_port = ntohs(payload.src_port);
                payload.dst_port = ntohs(payload.dst_port);

                payload.offset_flags = ntohs(payload.offset_flags);
                tcp_offset = (payload.offset_flags >> 12) * 4;
                
                urg_flag = (payload.offset_flags & 32);
                ack_flag = (payload.offset_flags & 16);
                psh_flag = (payload.offset_flags & 8); 
                rst_flag = (payload.offset_flags & 4); 
                syn_flag = (payload.offset_flags & 2); 
                fin_flag = (payload.offset_flags & 1);

                if(urg_flag != 0){
                    flags[count] = "URG";
                    count++;
                }
                if(ack_flag != 0){
                    flags[count] = "ACK";
                    count++;
                }

                if(psh_flag != 0){
                    flags[count] = "PSH";
                    count++;
                }

                if(rst_flag != 0){
                    flags[count] = "RST";
                    count++;
                }

                if(syn_flag != 0){
                    flags[count] = "SYN";
                    count++;
                }

                if(fin_flag != 0){
                    flags[count] = "FIN";
                    count++;
                }
        
                srcservice = TCP_Service(payload.src_port);
                dstservice = TCP_Service(payload.dst_port);
                
                printf("%s -> %s %d -> %d %s %s", src_ip_readable, dst_ip_readable, payload.src_port, payload.dst_port, srcservice, dstservice);
                for(int i=0; i < count; i++){
                    printf("%s ", flags[i]);
                }
                printf("\n");


            }

            free(transport_data);
             
        }
}
}