#include "controller.h"

int portNum;
pthread_mutex_t printMutex;
pthread_mutex_t networkGraphMutex;
pthread_mutex_t graphUpdatedMutex;
switchUp *globalSwitchList;
int wasUpdated;

int main (int args, char **argv) {

   if (args == 2) {
      portNum = atoi(argv[1]);
   }
   else if (args > 2) {
      fprintf(stderr, "Usage: ./controller {port_number}\n");
      exit(-1);
   }
   else {
      portNum = DEFAULT_OF_PORT;
   }

   startController();
   return 0;
}

int startController () {
   pthread_t threads[MAX_SWITCHES];
   int currThreads = 0;
   printf("Starting Controller on port %d\n", portNum);
   int serverSocketNum = startTCPSocket();
   printf("\tCreated a socket on port %d with Socket number %d\n", portNum, serverSocketNum);
   long clientSocketNum;

   wasUpdated = 0;

   pthread_mutex_init(&printMutex, NULL);
   pthread_mutex_init(&networkGraphMutex, NULL);
   pthread_mutex_init(&graphUpdatedMutex, NULL);

   while((clientSocketNum = acceptTCP(serverSocketNum))) {
      printf("\tAccepted connection with Socket Number %ld\n", clientSocketNum);
      pthread_create(&threads[currThreads], NULL, startConnection, (void *)clientSocketNum);
      currThreads++;
   }

   close(serverSocketNum);
   pthread_mutex_destroy(&printMutex);
   pthread_mutex_destroy(&networkGraphMutex);
   pthread_mutex_destroy(&graphUpdatedMutex);
   return 0;
}


void *startConnection(void *socket_info) {
   int flag = 1;
   fd_set rfds;
   struct timeval tv;
   //sockInfoThread *sockInfo = (sockInfoThread *) socket_info;
   int clientSocketNum = (long)socket_info;
   long switchId;

   printf("clientSocketNum %d\n", clientSocketNum);
   tv.tv_sec = 5;
   tv.tv_usec = 500;


   while (flag) {
      FD_ZERO(&rfds);
      FD_SET(clientSocketNum, &rfds);
      select(clientSocketNum + 1, &rfds, NULL, NULL, &tv);
      if (FD_ISSET(clientSocketNum, &rfds)) {
         unsigned char *packet = readPacketFromSocket(clientSocketNum);
         if (getTypeFromPacket(packet) == OFPT_HELLO) {
            printOFPacket(packet);
            struct ofp_header *helloP = (struct ofp_header *) packet;
            if (helloP->version != 0x4) {
               printf("Does not support versions other than 1.3\n");
               pthread_exit(NULL);
            }
            sendHelloResponse(clientSocketNum);
            sendFeaturesRequest(clientSocketNum);
            //sendPortConfigRequest(clientSocketNum);
            sendPortDescRequest(clientSocketNum);
            //sendConfigRequest(clientSocketNum);
         }
         else if (getTypeFromPacket(packet) == OFPT_ECHO_REQUEST) {
            printOFPacket(packet);
            sendEchoReply(clientSocketNum);
         }
         else if (getTypeFromPacket(packet) == OFPT_MULTIPART_REPLY) {
            printOFPacket(packet);
            struct ofp_multipart_reply *rep = (struct ofp_multipart_reply *) packet;
            printSwitchList();
            if (ntohs(rep->type) == OFPMP_PORT_STATS) {
               int numPorts = ((ntohs(rep->header.length) - sizeof(struct ofp_multipart_reply)) / sizeof(struct ofp_port_stats));
               int i = 0;
               for (i = 0; i < numPorts; i++) {
                  //addPortToListStats(switchId, (struct ofp_port_stats *)(rep->body + i * sizeof(struct ofp_port_stats)));
               }
            }
            else if (ntohs(rep->type) == OFPMP_PORT_DESC) {
               //Need to update with the mac address
               int numPorts = ((ntohs(rep->header.length) - sizeof(struct ofp_multipart_reply)) / sizeof(struct ofp_port));
               int i = 0;
               for (i = 0; i < numPorts; i++) {
                  struct ofp_port *port = (struct ofp_port *)(rep->body + i * sizeof(struct ofp_port));
                  addPortToListPort(switchId, *port);
                  addPortHwAddr(switchId, *port);
                  if ((ntohl(port->state) & OFPPS_LINK_DOWN) == 1) {
                     stateUpdatePortFromSwitch(switchId, ntohl(port->port_no), PORT_STAT_DOWN);
                  }
                  else if ((ntohl(port->state) & OFPPS_LINK_DOWN) == 0){
                     if ((ntohl(port->config) & OFPPC_PORT_DOWN) == 1) {
                        stateUpdatePortFromSwitch(switchId, ntohl(port->port_no), PORT_SUPPRESSED);
                     }
                     else {
                        stateUpdatePortFromSwitch(switchId, ntohl(port->port_no), PORT_SENDING);
                     }
                  }
               }
               topologyUpdated();
            }
            printSwitchList();
         }
         else if (getTypeFromPacket(packet) == OFPT_FEATURES_REPLY) {
            printOFPacket(packet);
            struct ofp_switch_features *features = (struct ofp_switch_features *) packet;
            switchId = ntohll(features->datapath_id);
            addSwitchToList(switchId);
         }
         else if (getTypeFromPacket(packet) == OFPT_PORT_STATUS) {
            printOFPacket(packet);
            struct ofp_port_status *port = (struct ofp_port_status *) packet;
            if (port->reason == OFPPR_MODIFY) {
               if ((ntohl(port->desc.state) & OFPPS_LINK_DOWN) == 1) {
                  stateUpdatePortFromSwitch(switchId, ntohl(port->desc.port_no), PORT_STAT_DOWN);
               }
               else if ((ntohl(port->desc.state) & OFPPS_LINK_DOWN) == 0){
                  if ((ntohl(port->desc.config) & OFPPC_PORT_DOWN) == 1) {
                     stateUpdatePortFromSwitch(switchId, ntohl(port->desc.port_no), PORT_SUPPRESSED);
                  }
                  else {
                     stateUpdatePortFromSwitch(switchId, ntohl(port->desc.port_no), PORT_SENDING);
                  }
               }
               addPortHwAddr(switchId, port->desc);
               topologyUpdated();
            }
            else if (port->reason == OFPPR_ADD) {
               addPortToListPort(switchId, port->desc);
               if ((ntohl(port->desc.state) & OFPPS_LINK_DOWN) == 1) {
                  stateUpdatePortFromSwitch(switchId, ntohl(port->desc.port_no), PORT_STAT_DOWN);
               }
               else if ((ntohl(port->desc.config) & OFPPC_PORT_DOWN) == 0){
                  if ((ntohl(port->desc.config) & OFPPC_PORT_DOWN) == 1) {
                     stateUpdatePortFromSwitch(switchId, ntohl(port->desc.port_no), PORT_SUPPRESSED);
                  }
                  else {
                     stateUpdatePortFromSwitch(switchId, ntohl(port->desc.port_no), PORT_SENDING);
                  }
               }
               addPortHwAddr(switchId, port->desc);
               topologyUpdated();
            }
            else {
               deletePortFromList(switchId, ntohl(port->desc.port_no));
               topologyUpdated();
            }
         }
         else {
            printOFPacket(packet);
         }


         if (packet != NULL) {
            free(packet);
         }
      }
      else {
         flag = 0;
      }
   }
   //free(sockInfo);
   pthread_exit(NULL);

}




void sendHelloResponse(int socketNum) {
   unsigned char buf[108];
   memset(buf, 0, sizeof(struct ofp_header) + sizeof(struct ofp_hello_elem_versionbitmap));

   struct ofp_header sendPacket;
   sendPacket.version = 0x4;
   sendPacket.type = OFPT_HELLO;
   sendPacket.length = ntohs(sizeof(struct ofp_header) + sizeof(uint32_t) + sizeof(struct ofp_hello_elem_header));
   sendPacket.xid = 0;

   struct ofp_hello_elem_header e;
   uint32_t bitmap = ntohl(0x10);

   e.type = ntohs(OFPHET_VERSIONBITMAP);
   e.length = ntohs(sizeof(struct ofp_hello_elem_header) + sizeof(uint32_t));
   memcpy(buf, &sendPacket, sizeof(struct ofp_header));
   memcpy(buf + sizeof(struct ofp_header), &e, sizeof(struct ofp_hello_elem_header));
   memcpy(buf + sizeof(struct ofp_header) + sizeof(struct ofp_hello_elem_header), &bitmap, sizeof(uint32_t));
   //printOFPacket(buf);
   sendPacketToSocket(socketNum, buf, sizeof(struct ofp_header) + sizeof(struct ofp_hello_elem_header) + sizeof(uint32_t));
}

void sendFeaturesRequest(int socketNum) {
   unsigned char buf[sizeof(struct ofp_header)];
   memset(buf, 0, sizeof(struct ofp_header));

   struct ofp_header sendPacket;
   sendPacket.version = 0x4;
   sendPacket.type = OFPT_FEATURES_REQUEST;
   sendPacket.length = ntohs(sizeof(struct ofp_header));
   sendPacket.xid = 0;

   memcpy(buf, &sendPacket, sizeof(struct ofp_header));

   sendPacketToSocket(socketNum, buf, sizeof(struct ofp_header));
}

void sendEchoReply(int socketNum) {
   unsigned char buf[sizeof(struct ofp_header)];
   memset(buf, 0, sizeof(struct ofp_header));

   struct ofp_header sendPacket;
   sendPacket.version = 0x4;
   sendPacket.type = OFPT_ECHO_REPLY;
   sendPacket.length = ntohs(sizeof(struct ofp_header));
   sendPacket.xid = 0;

   memcpy(buf, &sendPacket, sizeof(struct ofp_header));

   sendPacketToSocket(socketNum, buf, sizeof(struct ofp_header));
}

void sendConfigRequest(int socketNum) {
   unsigned char buf[sizeof(struct ofp_header)];
   memset(buf, 0, sizeof(struct ofp_header));

   struct ofp_header sendPacket;
   sendPacket.version = 0x4;
   sendPacket.type = OFPT_GET_CONFIG_REQUEST;
   sendPacket.length = htons(sizeof(struct ofp_header));
   sendPacket.xid = 0;

   memcpy(buf, &sendPacket, sizeof(struct ofp_header));

   sendPacketToSocket(socketNum, buf, sizeof(struct ofp_header));
}

void sendPortConfigRequest(int socketNum) {
   unsigned char buf[sizeof(struct ofp_multipart_request) + sizeof(struct ofp_port_stats_request)];
   memset(buf, 0, sizeof(struct ofp_multipart_request) + sizeof(struct ofp_port_stats_request));
   int i = 0;
   struct ofp_multipart_request req;
   req.header.version = 0x4;
   req.header.type = OFPT_MULTIPART_REQUEST;
   req.header.length = htons(sizeof(struct ofp_multipart_request) + sizeof(struct ofp_port_stats_request));
   req.header.xid = 0;
   req.type = htons(OFPMP_PORT_STATS);
   req.flags = 0;
   for (i = 0; i < 4; i++) {
      req.pad[i] = 0;
   }
   struct ofp_port_stats_request port_req;
   port_req.port_no = OFPP_ANY;

   memcpy(buf, &req, sizeof(struct ofp_multipart_request));
   memcpy(buf + sizeof(struct ofp_multipart_request), &port_req, sizeof(struct ofp_port_stats_request));
   sendPacketToSocket(socketNum, buf, sizeof(buf));

}

void sendPortDescRequest(int socketNum) {
   unsigned char buf[sizeof(struct ofp_multipart_request)];
   memset(buf, 0, sizeof(struct ofp_multipart_request));
   int i = 0;
   struct ofp_multipart_request req;
   req.header.version = 0x4;
   req.header.type = OFPT_MULTIPART_REQUEST;
   req.header.length = htons(sizeof(struct ofp_multipart_request));
   req.header.xid = 0;
   req.type = htons(OFPMP_PORT_DESC);
   req.flags = 0;
   for (i = 0; i < 4; i++) {
      req.pad[i] = 0;
   }
   memcpy(buf, &req, sizeof(struct ofp_multipart_request));
   sendPacketToSocket(socketNum, buf, sizeof(buf));
}

void addPortToListStats(long switchId, struct ofp_port_stats *stats) {
   pthread_mutex_lock(&networkGraphMutex);
   switchUp *temp = globalSwitchList;
   while (temp != NULL && temp->switchId != switchId) {
      temp = temp->next;
   }
   if (temp != NULL) {
      portUp *newPort = (portUp *) calloc(sizeof(portUp *), 1);
      newPort->next = temp->portList;
      newPort->portNum = ntohl(stats->port_no);
      newPort->state = PORT_STAT_UNKNOWN;
      temp->portList = newPort;
      memset(newPort->hw_addr, 0, OFP_ETH_ALEN);
   }
   pthread_mutex_unlock(&networkGraphMutex);
}

void addPortToListPort(long switchId, struct ofp_port p) {
   pthread_mutex_lock(&networkGraphMutex);
   switchUp *temp = globalSwitchList;
   while (temp != NULL && temp->switchId != switchId) {
      temp = temp->next;
   }
   if (temp != NULL) {
      portUp *newPort = (portUp *) calloc(sizeof(portUp *), 1);
      newPort->next = temp->portList;
      newPort->portNum = ntohl(p.port_no);
      newPort->state = PORT_STAT_UNKNOWN;
      temp->portList = newPort;
      memset(newPort->hw_addr, 0, OFP_ETH_ALEN);
   }
   pthread_mutex_unlock(&networkGraphMutex);
}

void addSwitchToList(long switchId) {
   printf("asdfasdfasdf\n");
   pthread_mutex_lock(&networkGraphMutex);
   switchUp *newSwitch = (switchUp *) calloc(sizeof(switchUp), 1);
   newSwitch->next = globalSwitchList;
   newSwitch->portList = NULL;
   newSwitch->switchId = switchId;
   globalSwitchList = newSwitch;
   pthread_mutex_unlock(&networkGraphMutex);
}

void stateUpdatePortFromSwitch(long switchId, long portNum, int state) {
   pthread_mutex_lock(&networkGraphMutex);
   switchUp *temp = globalSwitchList;
   while (temp != NULL && temp->switchId != switchId) {
      temp = temp->next;
   }
   if (temp != NULL) {
      portUp *tempP = temp->portList;
      while (tempP != NULL && tempP->portNum != portNum) {
         tempP = tempP->next;
      }
      if (tempP != NULL) {
         tempP->state = state;
      }
   }
   pthread_mutex_unlock(&networkGraphMutex);
}

void addPortHwAddr(long switchId, struct ofp_port p) {
   pthread_mutex_lock(&networkGraphMutex);
   switchUp *temp = globalSwitchList;
   while (temp != NULL && temp->switchId != switchId) {
      temp = temp->next;
   }
   if (temp != NULL) {
      portUp *tempP = temp->portList;
      while (tempP != NULL && tempP->portNum != ntohl(p.port_no)) {
         tempP = tempP->next;
      }
      if (tempP != NULL) {
         for (int i = 0; i < OFP_ETH_ALEN; i++) {
            tempP->hw_addr[i] = p.hw_addr[i];
         }
      }
   }
   pthread_mutex_unlock(&networkGraphMutex);
}

void deletePortFromList(long switchId, long portNum) {
   pthread_mutex_lock(&networkGraphMutex);
   switchUp *temp = globalSwitchList;
   while (temp != NULL && temp->switchId != switchId) {
      temp = temp->next;
   }
   if (temp != NULL) {
      portUp *tempP = temp->portList;
      portUp *prev = NULL;
      while (tempP != NULL && tempP->portNum != ntohl(portNum)) {
         prev = tempP;
         tempP = tempP->next;
      }
      if (tempP != NULL) {
         if (prev != NULL) {
            prev->next = tempP->next;
            free(tempP);
         }
         else {
            temp->portList = NULL;
            free(tempP);
         }

      }
   }
   pthread_mutex_unlock(&networkGraphMutex);
}

void topologyUpdated() {
   pthread_mutex_lock(&graphUpdatedMutex);
   wasUpdated++;
   pthread_mutex_unlock(&graphUpdatedMutex);
}
/*void sendPortDescriptionRequest(int socketNum) {

}*/







int startTCPSocket() {
   int socketNum = 0;
   struct sockaddr_in local;
   socklen_t len = sizeof(local);

   //Create Socket to listen for the checkConnections
   socketNum = socket(AF_INET, SOCK_STREAM, 0);
   if (socketNum < 0) {
      perror("Socket Call Failure");
      exit(1);
   }

   local.sin_family = AF_INET;
   local.sin_addr.s_addr = INADDR_ANY;
   local.sin_port = htons(portNum);

   //Bind the address to the port
   if (bind(socketNum, (struct sockaddr *) &local, sizeof(local)) < 0) {
      perror("Bind Call Failure");
      exit(-1);
   }

   //Get Port name and print it out
   if (getsockname(socketNum, (struct sockaddr *) &local, &len) < 0) {
      perror("GetSockName Call Failure");
      exit(-1);
   }

   if (listen(socketNum, 5) < 0) {
      perror("Listen Call Failure");
      exit(-1);
   }

   return socketNum;
}

int acceptTCP(int serverSocketNum) {
   int clientSocketNum = 0;
   if ((clientSocketNum = accept(serverSocketNum, (struct sockaddr *) 0, (socklen_t *) 0)) < 0) {
      perror("Accept Call Failure");
      exit(-1);
   }

   return clientSocketNum;
}

unsigned char *readPacketFromSocket(int socketNumber) {
   unsigned char buf[INIT_BUFF_SIZE];
   unsigned char *packet;
   int msgLen = 0;
   memset(buf, 0, INIT_BUFF_SIZE);


   if ((msgLen = recv(socketNumber, buf, sizeof(struct ofp_header), MSG_WAITALL)) < 0) {
      perror("Recv Call Failure");
      exit(-1);
   }
   if(msgLen == 0) {
      printf("MESSAGE LENGTH = 0");
   }
   struct ofp_header *header = (struct ofp_header *) buf;
   if (ntohs(header->length) != 0 && ntohs(header->length) - sizeof(struct ofp_header) > 0) {
      if ((msgLen = recv(socketNumber, &(buf[sizeof(struct ofp_header)]), ntohs(header->length) - sizeof(struct ofp_header), MSG_WAITALL)) < 0) {
         perror("Recv Call Failure");
         exit(-1);
      }
   }
   else if (ntohs(header->length) == 0) {
      packet = (unsigned char *) calloc(sizeof(char), sizeof(struct ofp_header));
      memcpy(packet, buf, sizeof(struct ofp_header));
      return packet;
   }
   packet = (unsigned char *) calloc(sizeof(char), ntohs(header->length));
   memcpy(packet, buf, ntohs(header->length));
   return packet;
}

void sendPacketToSocket(int socketNumber, unsigned char *packet, int packetSize) {
   int sent = 0;
   if ((sent = send(socketNumber, packet, packetSize, 0)) < 0) {
      perror("Send Packet Failed");
      exit(-1);
   }
}

int getTypeFromPacket(unsigned char *packet) {
   if (packet != NULL) {
      return packet[1];
   }
   else {
      perror("Get type from packet: NULL packet");
      exit(-1);
   }
}

void printOFPacket(unsigned char *packet) {
   int type = getTypeFromPacket(packet);
   pthread_mutex_lock(&printMutex);
   if (type == OFPT_HELLO) {
      struct ofp_header *hello= (struct ofp_header *)packet;
      printf("---Hello Packet---\n");
      printf("\tversion = %d\n", hello->version);
      printf("\ttype = %d\n", hello->type);
      printf("\tlen = %d\n", ntohs(hello->length));
      printf("\txid = %d\n", ntohl(hello->xid));
      printf("\t-Element-\n");
      struct ofp_hello_elem_versionbitmap *e= (struct ofp_hello_elem_versionbitmap *) (packet + sizeof(struct ofp_header));

      printf("\t\ttype = %d\n", ntohs(e->type));
      printf("\t\tlen = %d\n", ntohs(e->length));
      printf("\t\tbitmap = %x\n", ntohl(e->bitmaps[0]));
   }
   else if (type == OFPT_ERROR) {
      printf("---Error Packet---\n");
   }
   else if (type == OFPT_PACKET_IN && SHOW_PACKET_IN) {
      /*
      struct ofp_packet_in *in = (struct ofp_packet_in *) packet;
      printf("---Packet In---\n");
      printf("\tbuffer id = %d\n", ntohl(in->buffer_id));
      printf("\ttot_len = %d\n", ntohs(in->total_len));
      printf("\treason = ");
      if (in->reason == OFPR_ACTION) {
         printf("ACTION\n");
      }
      else if (in->reason == OFPR_NO_MATCH) {
         printf("NO MATCH\n");
      }
      else if (in->reason == OFPR_INVALID_TTL) {
         printf("INVALID TTL\n");
      }
      else {
         printf("invalid reason code\n");
      }
      printf("\ttable id = %d\n", in->table_id);
      printf("\tcookie = %llx\n", in->cookie);
      printf("\tmatch type = %d or ", ntohs(in->match.type));
      if (ntohs(in->match.type) == 1) {
         printf("OXM\n");
      }
      else {
         printf("STANDARD\n");
      }
      printf("\tmatch length = %d\n", ntohs(in->match.length));
      printf("\tmatch padding =\n");
      int i = 0;
      for (i = 0; i < 4; i++) {
         printf("\t\t--Padding %d--\n", i + 1);
         printf("\t\tOXM Class = %x\n", OXM_CLASS(in->match.pad[i]));
         printf("\t\tOXM Field = %d\n", OXM_FIELD(in->match.pad[i]));
         printf("\t\tOXM Length = %d\n", OXM_LENGTH(in->match.pad[i]));
      }
*/
      //analyzePacketP(in->data);
   }
   else if (type == OFPT_FEATURES_REPLY) {
      struct ofp_switch_features *features = (struct ofp_switch_features *) packet;
      printf("---Features Reply---\n");
      printf("\tdata path id = %llx\n", ntohll(features->datapath_id));
      printf("\tnumber of buffers = %d\n", ntohl(features->n_buffers));
      printf("\tnumber of tables = %d\n", features->n_tables);
      printf("\tauxiliary_id = %x\n", features->auxiliary_id);
      printf("\t\t--Capabilities--\n");
      printf("\t\tOFP Flow Stats = %d\n", ntohl(features->capabilities) & OFPC_FLOW_STATS && 1);
      printf("\t\tOFP Table Stats = %d\n", ntohl(features->capabilities) & OFPC_TABLE_STATS && 1);
      printf("\t\tOFP Port Stats = %d\n", ntohl(features->capabilities) & OFPC_PORT_STATS && 1);
      printf("\t\tOFP Group Stats = %d\n", ntohl(features->capabilities) & OFPC_GROUP_STATS && 1);
      printf("\t\tOFP IP Reassemble= %d\n", ntohl(features->capabilities) & OFPC_IP_REASM && 1);
      printf("\t\tOFP Queue Stats = %d\n", ntohl(features->capabilities) & OFPC_QUEUE_STATS && 1);
      printf("\t\tOFP Port Blocked = %d\n", ntohl(features->capabilities) & OFPC_PORT_BLOCKED && 1);

   }
   else if (type == OFPT_ECHO_REQUEST) {
      printf("---Echo Request---\n");

   }
   else if (type == OFPT_GET_CONFIG_REPLY) {
      printf("---Config Reply---\n");
   }
   else if (type == OFPT_PORT_STATUS) {
      struct ofp_port_status *port = (struct ofp_port_status *) packet;

      printf("---Port Status---\n");
      printf("\tReason = ");
      if (port->reason == OFPPR_ADD) {
         printf("ADD\n");
      }
      else if (port->reason == OFPPR_DELETE) {
         printf("DELETE\n");
      }
      else if (port->reason == OFPPR_MODIFY) {
         printf("MODIFY\n");
      }
      printOFPort(port->desc);

   }
   else if (type == OFPT_MULTIPART_REPLY) {
      struct ofp_multipart_reply *rep = (struct ofp_multipart_reply *) packet;
      printf("---Multipart Reply---\n");
      printf("\ttype = ");
      if (ntohs(rep->type) == OFPMP_PORT_STATS) {
         printf("PORT STATS\n");
         printf("\tflags = %x\n", rep->flags);
         int numPorts = ((ntohs(rep->header.length) - sizeof(struct ofp_multipart_reply)) / sizeof(struct ofp_port_stats));
         int i = 0;
         for (i = 0; i < numPorts; i++) {
            printOFPortStats((struct ofp_port_stats *)(rep->body + i * sizeof(struct ofp_port_stats)));
         }
      }
      else if (ntohs(rep->type) == OFPMP_PORT_DESC) {
         printf("PORT DESC\n");
         printf("\tflags = %x\n", rep->flags);
         int numPorts = ((ntohs(rep->header.length) - sizeof(struct ofp_multipart_reply)) / sizeof(struct ofp_port));
         int i = 0;
         for (i = 0; i < numPorts; i++) {
            printOFPort(*(struct ofp_port *)(rep->body + i * sizeof(struct ofp_port)));
         }
      }
      else {
         printf("UNSUPPORTED TYPE\n");
      }
   }
   else {
      printf("Could not print packet: Unknown packet type\n");
      printf("type = %d\n", type);
      return;
   }
   printf("-------------------\n");
   printf("\n");
   pthread_mutex_unlock(&printMutex);
}


void printOFPort(struct ofp_port p) {
   printf("\t--Port Desc--\n");
   printf("\t\tname = %s\n", p.name);
   printf("\t\tnumber = %d\n", ntohl(p.port_no));
   printf("\t\thardware addr = ");
   printf("%x", p.hw_addr[0]);
   int i = 0;
   for (i = 1; i < OFP_ETH_ALEN; i++) {
      printf(":%x", p.hw_addr[i]);
   }
   printf("\n");
   printf("\t\tconfig =");
   if ((ntohl(p.config) & OFPPC_PORT_DOWN)) {
      printf("-Port Down-");
   }
   if ((ntohl(p.config) & OFPPC_NO_RECV)) {
      printf("-No Recv-");
   }
   if ((ntohl(p.config) & OFPPC_NO_FWD)) {
      printf("-No Fwd-");
   }
   if ((ntohl(p.config) & OFPPC_NO_PACKET_IN)) {
      printf("-No Packet In-");
   }
   printf("\n");

   printf("\t\tstate = ");
   if ((ntohl(p.state) & OFPPS_LINK_DOWN)) {
      printf("-Link Down-");
   }
   if ((ntohl(p.state) & OFPPS_LIVE)) {
      printf("-Live-");
   }
   if ((ntohl(p.state) & OFPPS_BLOCKED)) {
      printf("-Blocked-");
   }
   printf("\n");
}

void printOFPortStats(struct ofp_port_stats *stats) {
   printf("\t--Port Number %d--\n", ntohl(stats->port_no));
   printf("\t\tnumber packets rx = %llu\n", ntohll(stats->rx_packets));
   printf("\t\tnumber packets tx = %llu\n", ntohll(stats->tx_packets));
   printf("\t\tnumber bytes rx = %llu\n", ntohll(stats->rx_bytes));
   printf("\t\tnumber bytes tx = %llu\n", ntohll(stats->tx_bytes));
   printf("\t\tnumber packets dropped rx = %llu\n", ntohll(stats->rx_dropped));
   printf("\t\tnumber packets dropped tx = %llu\n", ntohll(stats->tx_dropped));
   printf("\t\ttime port alive (s) = %u.%u\n", ntohl(stats->duration_sec), ntohl(stats->duration_nsec));
}

void printSwitchList() {
   switchUp *temp = globalSwitchList;
   pthread_mutex_lock(&networkGraphMutex);
   while(temp != NULL) {
      printf("--Switch %lx--\n", temp->switchId);
      printPortList(temp->portList);
      temp = temp->next;
   }
   pthread_mutex_unlock(&networkGraphMutex);
}

void printPortList(portUp *head) {
   portUp *temp = head;
   while (temp != NULL) {
      printf("\t--Port %ld--\n", temp->portNum);
      printf("\tState = %d\n", temp->state);
      printf("\thardware addr = ");
      printf("%x", temp->hw_addr[0]);
      int i = 0;
      for (i = 1; i < OFP_ETH_ALEN; i++) {
         printf(":%x", temp->hw_addr[i]);
      }
      printf("\n");
      temp = temp->next;
   }
}
