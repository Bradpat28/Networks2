#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>


#include "openflow.h"
#include "smartalloc.h"
#include "checksum.h"
#include "trace.h"


#define DEFAULT_OF_PORT 6653
#define INIT_BUFF_SIZE 2048


void sendHelloResponse(int socketNum);
void sendFeaturesRequest(int socketNum);
void sendEchoReply(int socketNum);
void sendConfigRequest(int socketNum);
void sendPortConfigRequest(int socketNum);
int startController();
int startTCPSocket();
int acceptTCP(int serverSocketNum);
unsigned char *readPacketFromSocket(int socketNum);
int getTypeFromPacket(unsigned char *packet);
void sendPacketToSocket(int socketNumber, unsigned char *packet, int packetSize);
void printOFPacket(unsigned char *packet);
void printOFPort(struct ofp_port p);
void printOFPortStats(struct ofp_port_stats *p);
