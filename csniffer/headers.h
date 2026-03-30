#ifndef HEADERS_H
#define HEADERS_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <netdb.h>
#include <stdlib.h>

void hexdump(const unsigned char* hex, int hexlength);
const char* UDP_Service(int port);
const char* TCP_Service(int port);

#endif