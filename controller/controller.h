#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/types.h>
#include <inttypes.h>


#include "openflow.h"
#include "smartalloc.h"
#include "checksum.h"
#include "trace.h"

#define MAX_SWITCHES 100
#define DEFAULT_OF_PORT 6653
#define INIT_BUFF_SIZE 2048

typedef struct sockInfoThread {
   int sockId;
}__attribute__((packed)) sockInfoThread;


void sendHelloResponse(int socketNum);
void sendFeaturesRequest(int socketNum);
void sendEchoReply(int socketNum);
void sendConfigRequest(int socketNum);
void sendPortConfigRequest(int socketNum);
int startController();
void *startConnection(void *socket_info);
int startTCPSocket();
int acceptTCP(int serverSocketNum);
unsigned char *readPacketFromSocket(int socketNum);
int getTypeFromPacket(unsigned char *packet);
void sendPacketToSocket(int socketNumber, unsigned char *packet, int packetSize);
void printOFPacket(unsigned char *packet);
void printOFPort(struct ofp_port p);
void printOFPortStats(struct ofp_port_stats *p);
