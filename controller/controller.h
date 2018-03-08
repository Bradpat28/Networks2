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

#define MAX_SWITCHES 100
#define DEFAULT_OF_PORT 6653
#define INIT_BUFF_SIZE 2048
#define SHOW_PACKET_IN 1
#define PORT_STAT_UNKNOWN 0
#define PORT_STAT_DOWN -1
#define PORT_SENDING 3
#define PORT_SUPPRESSED 2

typedef struct sockInfoThread {
   int sockId;
}__attribute__((packed)) sockInfoThread;

typedef struct portUp {
   long portNum;
   uint8_t hw_addr[OFP_ETH_ALEN];
   uint8_t port_addr[OFP_ETH_ALEN];
   int state;
   int isConnectToSwitch;
   long connectedSwitchId;
   int hasBeenAdded;
   struct portUp *next;
}__attribute__((packed)) portUp;

typedef struct switchUp {
   int socketNum;
   portUp *portList;
   int numPorts;
   long switchId;
   struct switchUp* next;
} __attribute__((packed)) switchUp;

typedef struct ethernetInfo {
   unsigned char mac_dest_host[OFP_ETH_ALEN];
   unsigned char mac_src_host[OFP_ETH_ALEN];
   uint16_t ether_type;
} __attribute__((packed)) ethernetInfo;

typedef struct switchProbePacket {
   ethernetInfo e;
   uint64_t switchId;
   uint32_t portNum;
} __attribute__((packed)) switchProbePacket;

typedef struct treeConstruct {
   long fromSwitch;
   long toSwitch;
   struct treeConstruct *next;
} __attribute__((packed)) treeConstruct;

typedef struct idList {
   long id;
   struct idList *next;
} __attribute__((packed)) idList;

typedef struct removePortCommand {
   long switchId;
   long *portNums;
} __attribute__ ((packed)) removePortCommand;

void sendHelloResponse(int socketNum);
void sendFeaturesRequest(int socketNum);
void sendEchoReply(int socketNum);
void sendConfigSet(int socketNum);
void sendPortConfigRequest(int socketNum);
void sendPortDescRequest(int socketNum);
void sendProbePacket(int socketNum, long switchId, int portNum, uint8_t hw_addr[OFP_ETH_ALEN]);
void sendFlowModAdd(int socketNum, int portNum,  uint8_t hw_addr[OFP_ETH_ALEN]);
void sendFlowModAddDefaultController(int socketNum, uint8_t tableId);
void sendFlowModAddPorts(int socketNum, uint32_t *portNums, int numPorts, uint8_t hw_addr[OFP_ETH_ALEN]);
void sendFlowModAddSrcLearn(int socketNum, uint8_t hw_addr[OFP_ETH_ALEN]);
void sendFlowModDeleteBroadcast(int socketNum, uint32_t *portNums, int numPorts);
void sendFlowModDeleteAll(int socketNum);


void addPortToListStats(long switchId, struct ofp_port_stats *stats);
void addPortToListPort(long switchId, struct ofp_port p);
void addSwitchToList(long switchId, int socketNum);
void addSwitchConnection(long switchId, int portId, long connectedSwitchId);
int checkInTree(treeConstruct *head, long fromSwitch, long toSwitch);
int inTree(treeConstruct *head, long id);
treeConstruct *addToTree(treeConstruct *head, long fromSwitch, long toSwitch, long portNum);
idList *getListOfConnect(treeConstruct *head, long fromSwitch);
void clearTree(treeConstruct *head);
void stateUpdatePortFromSwitch(long switchId, long portNum, int state);
void addPortHwAddr(long switchId, struct ofp_port p);
void addPortHwAddrInfo(long switchId, int portNum, uint8_t hw_addr[OFP_ETH_ALEN]);
void deletePortFromList(long switchId, long portNum);
void topologyUpdated();


int startController();
void *startGraphThread(void *args);
void *startConnection(void *socket_info);
int startTCPSocket();
int acceptTCP(int serverSocketNum);
unsigned char *readPacketFromSocket(int socketNum);
int getTypeFromPacket(unsigned char *packet);
void sendPacketToSocket(int socketNumber, unsigned char *packet, int packetSize);
void printOFPacket(unsigned char *packet);
void printOFPort(struct ofp_port p);
void printOFPortStats(struct ofp_port_stats *p);
void printSwitchList();
void printPortList(portUp *head);
