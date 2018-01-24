#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "trace.h"
#include <arpa/inet.h>
#include "smartalloc.h"

#define BUFF_SIZE 1000
#define PACKET_SIZE 1024
#define START 1
#define RESPOND_ARP 2
#define LOOK_FOR_ICMP 3

void packetController(unsigned char *pcap, const struct pcap_pkthdr *header,
   const unsigned char *packet);
int compareIP(unsigned char *ip, unsigned char* ipByte);
unsigned char *contructPacket(unsigned char *pcap, arpInfo *arp);
