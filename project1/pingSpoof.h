#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "trace.h"
#include <arpa/inet.h>
#include "smartalloc.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define BUFF_SIZE 1024
#define PACKET_SIZE 1024
#define START 1
#define RESPOND_ARP 2
#define LOOK_FOR_ICMP 3

void packetController(unsigned char *pcap, const struct pcap_pkthdr *header,
   const unsigned char *packet);
int compareIP(unsigned char *ip, unsigned char* ipByte);
unsigned char *constructPacket(unsigned char *pcap, arpInfo *arp);
void sendPacketARP(unsigned char *packet);
unsigned char *constructICMP(unsigned char *pcap, ethernetInfo *ether);
void sendPacketIP(unsigned char *packet);
