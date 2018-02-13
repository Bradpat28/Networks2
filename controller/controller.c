#include "controller.h"

int portNum;

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

}

int startController () {
   int flag = 1;
   fd_set rfds;
   struct timeval tv;

   tv.tv_sec = 1;
   tv.tv_usec = 500;

   printf("Starting Controller on port %d\n", portNum);
   int serverSocketNum = startTCPSocket();
   printf("\tCreated a socket on port %d with Socket number %d\n", portNum, serverSocketNum);

   int clientSocketNum = acceptTCP(serverSocketNum);
   printf("\tAccepted connection with Socket Number %d\n", clientSocketNum);
   while (flag) {
      FD_ZERO(&rfds);
      FD_SET(clientSocketNum, &rfds);
      select(clientSocketNum + 1, &rfds, NULL, NULL, &tv);
      if (FD_ISSET(clientSocketNum, &rfds)) {
         unsigned char *packet = readPacketFromSocket(clientSocketNum);
         if (getTypeFromPacket(packet) == OFPT_HELLO) {
            printOFPacket(packet);
            sendHelloResponse(clientSocketNum);
            sendFeaturesRequest(clientSocketNum);
            //sendConfigRequest(clientSocketNum);
         }
         else if (getTypeFromPacket(packet) == OFPT_ECHO_REQUEST) {
            printOFPacket(packet);
            sendEchoReply(clientSocketNum);

         }
         else {
            printOFPacket(packet);

         }
         if (packet != NULL) {
            free(packet);
         }
      }
   }
   close(serverSocketNum);
   return 0;
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
   sendPacket.length = ntohs(sizeof(struct ofp_header));
   sendPacket.xid = 0;

   memcpy(buf, &sendPacket, sizeof(struct ofp_header));

   sendPacketToSocket(socketNum, buf, sizeof(struct ofp_header));
}







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
   else if (type == OFPT_PACKET_IN) {
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
      for (int i = 0; i < 4; i++) {
         printf("\t\t--Padding %d--\n", i + 1);
         printf("\t\tOXM Class = %x\n", OXM_CLASS(in->match.pad[i]));
         printf("\t\tOXM Field = %d\n", OXM_FIELD(in->match.pad[i]));
         printf("\t\tOXM Length = %d\n", OXM_LENGTH(in->match.pad[i]));
      }

      //analyzePacketP(in->data);
   }
   else if (type == OFPT_FEATURES_REPLY) {
      struct ofp_switch_features *features = (struct ofp_switch_features *) packet;
      printf("---Features Reply---\n");
      printf("\tdata path id = %llx\n", features-> datapath_id);
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
   else {
      printf("Could not print packet: Unknown packet type\n");
      printf("type = %d\n", type);
      return;
   }
   printf("-------------------\n");
   printf("\n");
}


void printOFPort(struct ofp_port p) {
   printf("\t--Port Desc--\n");
   printf("\t\tname = %s\n", p.name);
   printf("\t\tnumber = %d\n", ntohl(p.port_no));
   printf("\t\thardware addr = ");
   printf("%x", p.hw_addr[0]);
   for (int i = 1; i < OFP_ETH_ALEN; i++) {
      printf(":%x", p.hw_addr[i]);
   }
   printf("\n");
   printf("\t\tconfig =");
   if (p.config & OFPPC_PORT_DOWN) {
      printf("-Port Down-");
   }
   if (p.config & OFPPC_NO_RECV) {
      printf("-No Recv-");
   }
   if (p.config & OFPPC_NO_FWD) {
      printf("-No Fwd-");
   }
   if (p.config & OFPPC_NO_PACKET_IN) {
      printf("-No Packet In-");
   }
   printf("\n");

   printf("\t\tstate = ");
   if (p.state & OFPPS_LINK_DOWN) {
      printf("-Link Down-");
   }
   if (p.state & OFPPS_LIVE) {
      printf("-Live-");
   }
   if (p.state & OFPPS_BLOCKED) {
      printf("-Blocked-");
   }
   printf("\n");
}