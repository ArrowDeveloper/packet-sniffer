#include "headers.h"

void hexdump(const unsigned char* hex, int hexlength){
    int i = 0;
    for(i = 0; i < hexlength; i++){
        printf("%d: %02x ", i, hex[i]);
        if((i+1) % 16 == 0){
            printf("\n");
        }
    }
}

struct Entry{
    int key;
    const char *value;
};

static struct Entry UDPservices[] = {
    {53, "DNS"},
    {67, "DHCP"},
    {68, "DHCP"},
    {69, "TFTP"}
};

const char* UDP_Service(int port){
    int count = sizeof(UDPservices) / sizeof(UDPservices[0]);

        for(int i=0; i < count; i ++){
            if(UDPservices[i].key == port){
                return UDPservices[i].value;
            }
        }

    return "UNKNOWN";
}

static const char* TCPservices[65535] = {
    [80] = "HTTP",
    [8080] = "HTTP",
    [22] = "SSH",
    [23] = "Telnet",
    [25] = "SMTP",
    [53] ="DNS",
    [3306] = "MySQL",
    [20] = "FTP",
    [21] = "FTP",
    [443] = "HTTPS"
};

const char* TCP_Service(int port){
    if(port < 0 || port > 65535){
        return NULL;
    }

    if(TCPservices[port] == NULL){
        return "UNKNOWN";
    }
    return TCPservices[port];

}
