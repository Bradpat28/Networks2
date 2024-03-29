#include "controller.h"

int portNum;
pthread_mutex_t printMutex;
pthread_mutex_t networkGraphMutex;
pthread_mutex_t graphUpdatedMutex;
pthread_cond_t cond;
switchUp *globalSwitchList;
removePortCommand *globalRemoveCommandList;
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
   pthread_t graphThread[1];
   int currThreads = 0;
   printf("Starting Controller on port %d\n", portNum);
   int serverSocketNum = startTCPSocket();
   printf("\tCreated a socket on port %d with Socket number %d\n", portNum, serverSocketNum);
   long clientSocketNum;

   wasUpdated = 0;

   pthread_mutex_init(&printMutex, NULL);
   pthread_mutex_init(&networkGraphMutex, NULL);
   pthread_mutex_init(&graphUpdatedMutex, NULL);
   pthread_cond_init(&cond, NULL);

   pthread_create(&graphThread[0], NULL, startGraphThread, NULL);

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

void *startGraphThread(void *args) {
   printf("GRAPH THREAD BEGINS\n");
   printSwitchList();

   while (1) {
      printf("%s\n", "Waiting");
      pthread_cond_wait(&cond, &networkGraphMutex);
      printf("UPDATING GRAPH\n");
      treeConstruct *broadcastChange = NULL;
      treeConstruct *head = NULL;
      switchUp *temp = globalSwitchList;
      while (temp != NULL) {
         if (temp->numPorts >= 2) {
            switchUp *switchIter = globalSwitchList;
            while (switchIter != NULL) {
               if (switchIter->switchId != temp->switchId) {
                  treeConstruct minDist = findMinHopLen(temp->switchId, switchIter->switchId, -1);
                  if (minDist.fromSwitch != -1) {
                     printf("MIN DIST FROM %ld -> %ld is port %ld for %ld\n", temp->switchId, switchIter->switchId, minDist.fromSwitch, minDist.toSwitch);
                     portUp *portIter = switchIter->portList;
                     while (portIter != NULL) {
                        if (!portIter->isConnectToSwitch && portIter->state == PORT_SENDING) {

                           sendFlowModShortestUnicast(temp->socketNum, (void *)&minDist.fromSwitch, 1, portIter->hw_addr);
                        }
                        portIter = portIter->next;
                     }
                  }
               }

               switchIter = switchIter->next;
            }
         }


         //Spanning TREE
         portUp *ports = temp->portList;
         while (ports != NULL) {
            if (ports->isConnectToSwitch == 1 && ports->hasBeenAdded != 1) {
               if (checkInTree(head, temp->switchId, ports->connectedSwitchId) ||
                     checkInTree(head, ports->connectedSwitchId,temp->switchId)) {
                  printf("\n\n\n\n\n---------------LOOP %ld -> %ld\n\n\n\n\n", temp->switchId, ports->connectedSwitchId);
                  treeConstruct *fix = (treeConstruct *) calloc(sizeof(treeConstruct), 1);
                  fix->fromSwitch = temp->switchId;
                  fix->toSwitch = ports->portNum;
                  fix->next = broadcastChange;
                  broadcastChange = fix;
               }
               else {
                  head = addToTree(head, temp->switchId, ports->connectedSwitchId, ports->portNum);
               }
            }
            ports = ports->next;
         }
         temp = temp->next;
      }
      treeConstruct *temp2 = head;
      printf("------------LINK GRAPH-----------\n");
      while (temp2 != NULL) {
         printf("---<%ld, %ld>---\n", temp2->fromSwitch, temp2->toSwitch);
         temp2 = temp2->next;
      }
      printf("-------------------------\n");

      treeConstruct *broadcastIter = broadcastChange;

      while (broadcastIter != NULL) {
         //find switch
         temp = globalSwitchList;
         while (temp != NULL && temp->switchId != broadcastIter->fromSwitch) {
            temp = temp->next;
         }
         if (temp != NULL) {
            uint32_t *ports = (uint32_t *) calloc(sizeof(uint32_t), temp->numPorts);
            int count = 0;
            portUp *portIter = temp->portList;
            while (portIter != NULL) {
               if (portIter->portNum != broadcastIter->toSwitch) {
                  ports[count] = portIter->portNum;
                  count++;
               }
               portIter = portIter->next;
            }

            sendFlowModDeleteBroadcast(temp->socketNum, ports, count);
            free(ports);
         }
         broadcastIter = broadcastIter->next;
      }


      clearTree(head);
      pthread_mutex_unlock(&networkGraphMutex);
      printSwitchList();
      printf("-----------------------------------------\n");
   }

   pthread_exit(NULL);
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
            sendFlowModDeleteAll(clientSocketNum);
            //sendConfigSet(clientSocketNum);
            sendFlowModAddDefaultController(clientSocketNum, 0);
            sendFlowModAddDefaultController(clientSocketNum, 1);
            sendPortDescRequest(clientSocketNum);
         }
         else if (getTypeFromPacket(packet) == OFPT_ECHO_REQUEST) {
            printOFPacket(packet);
            sendEchoReply(clientSocketNum);
         }
         else if (getTypeFromPacket(packet) == OFPT_MULTIPART_REPLY) {
            printOFPacket(packet);
            struct ofp_multipart_reply *rep = (struct ofp_multipart_reply *) packet;
            if (ntohs(rep->type) == OFPMP_PORT_STATS) {
               int numPorts = ((ntohs(rep->header.length) - sizeof(struct ofp_multipart_reply)) / sizeof(struct ofp_port_stats));
               int i = 0;
               for (i = 0; i < numPorts; i++) {
                  //addPortToListStats(switchId, (struct ofp_port_stats *)(rep->body + i * sizeof(struct ofp_port_stats)));
               }
            }
            else if (ntohs(rep->type) == OFPMP_PORT_DESC) {
               int numPorts = ((ntohs(rep->header.length) - sizeof(struct ofp_multipart_reply)) / sizeof(struct ofp_port));
               int i = 0;
               int numActualPorts = 0;
               uint32_t *portNums = (uint32_t *) calloc(numPorts, sizeof(uint32_t));
               for (i = 0; i < numPorts; i++) {
                  struct ofp_port *port = (struct ofp_port *)(rep->body + i * sizeof(struct ofp_port));
                  if (ntohl(port->port_no) != OFPP_LOCAL) {
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
                     sendProbePacket(clientSocketNum, switchId, ntohl(port->port_no), port->hw_addr);
                     //sendFlowModAdd(clientSocketNum, port->port_no, port->hw_addr);
                     portNums[numActualPorts] = ntohl(port->port_no);
                     numActualPorts++;
                  }
               }
               uint8_t broadcast_addr[OFP_ETH_ALEN];
               for (int i = 0; i < OFP_ETH_ALEN; i++) {
                  broadcast_addr[i] = 0xff;
               }
               sendFlowModAddPorts(clientSocketNum, portNums, numActualPorts, broadcast_addr);
               free(portNums);
               //topologyUpdated();

            }
         }
         else if (getTypeFromPacket(packet) == OFPT_FEATURES_REPLY) {
            printOFPacket(packet);
            struct ofp_switch_features *features = (struct ofp_switch_features *) packet;
            switchId = ntohl(features->datapath_id>> 32);
            printf("Switch ID = %lx\n", switchId);
            addSwitchToList(switchId, clientSocketNum);
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
         else if (getTypeFromPacket(packet) == OFPT_PACKET_IN) {
            //printOFPacket(packet);
            struct ofp_packet_in *in = (struct ofp_packet_in *) packet;
            //TODO FIGURE OUT PACKET IN
            if (in->reason == OFPR_NO_MATCH) {
               int headerLen = ntohs(in->header.length);
               int totalLen = ntohs(in->total_len);
               //int matchLen = ntohs(in->match.length);
               uint8_t *data = &packet[headerLen - totalLen];
               uint8_t src_addr[OFP_ETH_ALEN];
               uint32_t *oxm = (void *)&packet[sizeof(struct ofp_packet_in)];
               if (oxm[-1] == ntohl(OXM_OF_IN_PORT)) {
                  int portNum = ntohl(oxm[0]);
                  for (int i = 0; i < OFP_ETH_ALEN; i++) {
                     src_addr[i] = data[i + OFP_ETH_ALEN];
                  }
                  int equal = 1;
                  for (int i = 0; i < OFP_ETH_ALEN; i++) {
                     if (src_addr[i] != 0xfe) {
                        equal = 0;
                     }
                  }
                  if (equal) {
                     switchProbePacket *probe = (void*) data;
                     addSwitchConnection(switchId, portNum, probe->switchId);
                     addSwitchConnection(probe->switchId, probe->portNum, switchId);
                     topologyUpdated();

                  }
                  else {
                     addPortHwAddrInfo(switchId, portNum, src_addr);
                     sendFlowModAdd(clientSocketNum, portNum, src_addr);
                     sendFlowModAddSrcLearn(clientSocketNum, src_addr);
                     //topologyUpdated();
                  }

               }
            }

         }
         else {
            printOFPacket(packet);
         }
         if (packet != NULL) {
            free(packet);
            packet = NULL;
         }
      }
      else {
         //flag = 0;
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

void sendConfigSet(int socketNum) {
   unsigned char buf[sizeof(struct ofp_switch_config)];
   memset(buf, 0, sizeof(buf));

   struct ofp_switch_config *sendPacket = (void *)buf;
   sendPacket->header.version = 0x4;
   sendPacket->header.type = OFPT_SET_CONFIG;
   sendPacket->header.length = htons(sizeof(struct ofp_switch_config));
   sendPacket->header.xid = 0;
   sendPacket->flags = 0;
   sendPacket->miss_send_len = OFPCML_NO_BUFFER;

   sendPacketToSocket(socketNum, buf, sizeof(buf));
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

void sendProbePacket(int socketNum, long switchId, int portNum, uint8_t hw_addr[OFP_ETH_ALEN]) {
   unsigned char buf[sizeof(struct ofp_packet_out) + sizeof(switchProbePacket) + sizeof(struct ofp_action_output)];
   memset(buf, 0, sizeof(struct ofp_packet_out));

   struct ofp_packet_out *p = (void *)buf;
   p->header.version = 0x4;
   p->header.type = OFPT_PACKET_OUT;
   p->header.length = htons(sizeof(struct ofp_packet_out) + sizeof(struct ofp_action_output) + sizeof(switchProbePacket));
   p->header.xid = 0;

   p->buffer_id = OFP_NO_BUFFER;
   p->in_port = ntohl(OFPP_CONTROLLER);//portNum;
   p->actions_len = ntohs(sizeof(struct ofp_action_output));

   struct ofp_action_output *out = (void *)(buf + sizeof(struct ofp_packet_out));
   out->type = OFPAT_OUTPUT;
   out->len = ntohs(sizeof(struct ofp_action_output));
   out->port = htonl(portNum);
   out->max_len = 0;//= ntohs(sizeof(switchProbePacket));

   switchProbePacket *probe = (void *)(buf + sizeof(struct ofp_packet_out) + sizeof(struct ofp_action_output));
   memcpy(probe->e.mac_dest_host, hw_addr, OFP_ETH_ALEN);
   for (int i = 0; i < OFP_ETH_ALEN; i++) {
      probe->e.mac_src_host[i] = 0xFE;
   }
   probe->switchId = switchId;
   probe->portNum = portNum;

   sendPacketToSocket(socketNum, buf, sizeof(buf));
}

void sendFlowModAdd(int socketNum, int portNum, uint8_t hw_addr[OFP_ETH_ALEN]) {
   unsigned char buf[sizeof(struct ofp_flow_mod) + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output) + sizeof(struct ofp_instruction_goto_table)];
   memset(buf, 0, sizeof(buf));

   struct ofp_flow_mod *flow = (void *)buf;
   flow->header.version = 0x4;
   flow->header.type = OFPT_FLOW_MOD;
   flow->header.length = htons(sizeof(buf));
   flow->header.xid = 0;
   flow->cookie = 0xf;
   flow->priority = htons(OFP_DEFAULT_PRIORITY);
   flow->table_id = 0;
   flow->command = OFPFC_ADD;
   flow->idle_timeout = ntohs(0);
   flow->hard_timeout = ntohs(0);
   flow->buffer_id = OFP_NO_BUFFER;
   flow->out_port = OFPP_ANY;
   flow->out_group = OFPG_ANY;
   flow->flags = htons(OFPFF_SEND_FLOW_REM);

   flow->match.type = ntohs(OFPMT_OXM);
   flow->match.length = htons(sizeof(struct ofp_match) + OFP_ETH_ALEN);
    //sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output));
   uint32_t *temp = (void *) (buf + sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match) + sizeof(uint32_t));
   uint16_t *temp2 = (void *)temp;
   temp2[0]= htonl(OXM_OF_ETH_DST);
   temp2[1] = htonl(OXM_OF_ETH_DST)>>16;
   uint8_t *addr = (void *)&temp2[2];
   for (int i = 0; i < OFP_ETH_ALEN; i++) {
      addr[i] = hw_addr[i];
   }
   struct ofp_instruction_actions *instr = (void *)(buf + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_flow_mod));
   instr->type = ntohs(OFPIT_APPLY_ACTIONS);
   instr->len = htons(sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output));
   struct ofp_action_output *act = (void *) (buf + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions));
   act->type = OFPAT_OUTPUT;
   act->len= htons(sizeof(struct ofp_action_output));
   act->port = htonl(portNum);
   act->max_len = OFPCML_MAX;

   int loc = OFP_ETH_ALEN + 2 + sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output);
   struct ofp_instruction_goto_table *instr2 = (void *) (buf + loc);
   instr2->type = ntohs(OFPIT_GOTO_TABLE);
   instr2->len = htons(sizeof(struct ofp_instruction_goto_table));
   instr2->table_id = 1;

   sendPacketToSocket(socketNum, buf, sizeof(buf));
}

void sendFlowModAddPorts(int socketNum, uint32_t *portNums, int numPorts, uint8_t hw_addr[OFP_ETH_ALEN]) {
   unsigned char buf[sizeof(struct ofp_flow_mod) + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_instruction_actions) + numPorts * sizeof(struct ofp_action_output) + sizeof(struct ofp_instruction_goto_table)];
   memset(buf, 0, sizeof(buf));

   struct ofp_flow_mod *flow = (void *)buf;
   flow->header.version = 0x4;
   flow->header.type = OFPT_FLOW_MOD;
   flow->header.length = htons(sizeof(buf));
   flow->header.xid = 0;
   flow->cookie = 0xf;
   flow->priority = htons(OFP_DEFAULT_PRIORITY);
   flow->table_id = 0;
   flow->command = OFPFC_ADD;
   flow->idle_timeout = ntohs(0);
   flow->hard_timeout = ntohs(0);
   flow->buffer_id = OFP_NO_BUFFER;
   flow->out_port = htonl(OFPP_ANY);
   flow->out_group = htonl(OFPG_ANY);
   flow->flags = htons(OFPFF_SEND_FLOW_REM);

   flow->match.type = ntohs(OFPMT_OXM);
   flow->match.length = htons(sizeof(struct ofp_match) + OFP_ETH_ALEN);
   uint16_t *temp2 = (void *) (buf + sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match) + sizeof(uint32_t));
   temp2[0]= htonl(OXM_OF_ETH_DST);
   temp2[1] = htonl(OXM_OF_ETH_DST)>>16;
   uint8_t *addr = (void *)&temp2[2];
   for (int i = 0; i < OFP_ETH_ALEN; i++) {
      addr[i] = hw_addr[i];
   }

   //flow->match.oxm_fields = OXM_OF_ETH_DST;
   struct ofp_instruction_actions *instr = (void *)(buf + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_flow_mod));
   instr->type = ntohs(OFPIT_APPLY_ACTIONS);
   instr->len = htons(sizeof(struct ofp_instruction_actions) + numPorts * sizeof(struct ofp_action_output));
   for (int i = 0; i < numPorts; i++) {
      struct ofp_action_output *act = (void *) (buf + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions) + i *sizeof(struct ofp_action_output));
      act->type = OFPAT_OUTPUT;
      act->len= htons(sizeof(struct ofp_action_output));
      act->port = htonl(portNums[i]);
      act->max_len = OFPCML_MAX;
   }

   int loc = OFP_ETH_ALEN + 2 + sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions) + numPorts * sizeof(struct ofp_action_output);
   struct ofp_instruction_goto_table *instr2 = (void *) (buf + loc);
   instr2->type = ntohs(OFPIT_GOTO_TABLE);
   instr2->len = htons(sizeof(struct ofp_instruction_goto_table));
   instr2->table_id = 1;

   sendPacketToSocket(socketNum, buf, sizeof(buf));
}

void sendFlowModAddDefaultController(int socketNum, uint8_t tableId) {
   unsigned char buf[sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output)];
   memset(buf, 0, sizeof(buf));

   struct ofp_flow_mod *flow = (void *)buf;
   flow->header.version = 0x4;
   flow->header.type = OFPT_FLOW_MOD;
   flow->header.length = htons(sizeof(buf));
   flow->header.xid = 0;
   flow->cookie = 0xf;
   flow->priority = 0;
   flow->table_id = tableId;
   flow->command = OFPFC_ADD;
   flow->idle_timeout = ntohs(0);
   flow->hard_timeout = ntohs(0);
   flow->buffer_id = OFP_NO_BUFFER;
   flow->out_port = OFPP_ANY;
   flow->out_group = OFPG_ANY;
   flow->flags = htons(OFPFF_SEND_FLOW_REM);

   flow->match.type = ntohs(OFPMT_OXM);
   flow->match.length = htons(sizeof(struct ofp_match) - 4);
    //sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output));
   //uint32_t *temp = (void *) (buf + sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match) + sizeof(uint32_t));
   //printf("-------%lx\n\n\n", ((UINT64_C(1) << 40) - 1));
   //temp[0] = htonl(OXM_HEADER(OFPXMC_OPENFLOW_BASIC,-1,0));



   //flow->match.oxm_fields = OXM_OF_ETH_DST;
   struct ofp_instruction_actions *instr = (void *)(buf + sizeof(struct ofp_flow_mod));
   instr->type = ntohs(OFPIT_APPLY_ACTIONS);
   instr->len = htons(sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output));
   struct ofp_action_output *act = (void *) (buf + sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions));
   act->type = OFPAT_OUTPUT;
   act->len= htons(sizeof(struct ofp_action_output));
   act->port = htonl(OFPP_CONTROLLER);
   act->max_len = OFPCML_MAX;

   sendPacketToSocket(socketNum, buf, sizeof(buf));

}

void sendFlowModAddSrcLearn(int socketNum, uint8_t hw_addr[OFP_ETH_ALEN]) {
   unsigned char buf[sizeof(struct ofp_flow_mod) + OFP_ETH_ALEN  + 2];
   memset(buf, 0, sizeof(buf));

   struct ofp_flow_mod *flow = (void *)buf;
   flow->header.version = 0x4;
   flow->header.type = OFPT_FLOW_MOD;
   flow->header.length = htons(sizeof(buf));
   flow->header.xid = 0;
   flow->cookie = 0xf;
   flow->priority = htons(OFP_DEFAULT_PRIORITY);
   flow->table_id = 1;
   flow->command = OFPFC_ADD;
   flow->idle_timeout = ntohs(0);
   flow->hard_timeout = ntohs(0);
   flow->buffer_id = OFP_NO_BUFFER;
   flow->out_port = OFPP_ANY;
   flow->out_group = OFPG_ANY;
   flow->flags = htons(OFPFF_SEND_FLOW_REM);

   flow->match.type = ntohs(OFPMT_OXM);
   flow->match.length = htons(sizeof(struct ofp_match) + OFP_ETH_ALEN);
    //sizeof(struct ofp_instruction_actions) + sizeof(struct ofp_action_output));
   uint32_t *temp = (void *) (buf + sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match) + sizeof(uint32_t));
   uint16_t *temp2 = (void *)temp;
   temp2[0]= htonl(OXM_OF_ETH_SRC);
   temp2[1] = htonl(OXM_OF_ETH_SRC)>>16;
   uint8_t *addr = (void *)&temp2[2];
   for (int i = 0; i < OFP_ETH_ALEN; i++) {
      addr[i] = hw_addr[i];
   }

   sendPacketToSocket(socketNum, buf, sizeof(buf));
}

void sendFlowModDeleteBroadcast(int socketNum, uint32_t *portNums, int numPorts) {
   unsigned char buf[sizeof(struct ofp_flow_mod) + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_instruction_actions) + numPorts * sizeof(struct ofp_action_output) + sizeof(struct ofp_instruction_goto_table)];
   memset(buf, 0, sizeof(buf));

   struct ofp_flow_mod *flow = (void *)buf;
   flow->header.version = 0x4;
   flow->header.type = OFPT_FLOW_MOD;
   flow->header.length = htons(sizeof(buf));
   flow->header.xid = 0;
   flow->cookie = 0xf;
   flow->priority = htons(OFP_DEFAULT_PRIORITY);
   flow->table_id = 0;
   flow->command = OFPFC_MODIFY;
   flow->idle_timeout = ntohs(0);
   flow->hard_timeout = ntohs(0);
   flow->buffer_id = OFP_NO_BUFFER;
   flow->out_port = htonl(OFPP_ANY);
   flow->out_group = htonl(OFPG_ANY);
   flow->flags = htons(OFPFF_SEND_FLOW_REM);

   flow->match.type = ntohs(OFPMT_OXM);
   flow->match.length = htons(sizeof(struct ofp_match) + OFP_ETH_ALEN);
   uint16_t *temp2 = (void *) (buf + sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match) + sizeof(uint32_t));
   temp2[0]= htonl(OXM_OF_ETH_DST);
   temp2[1] = htonl(OXM_OF_ETH_DST)>>16;
   uint8_t *addr = (void *)&temp2[2];
   for (int i = 0; i < OFP_ETH_ALEN; i++) {
      addr[i] = 0xff;
   }

   //flow->match.oxm_fields = OXM_OF_ETH_DST;
   struct ofp_instruction_actions *instr = (void *)(buf + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_flow_mod));
   instr->type = ntohs(OFPIT_APPLY_ACTIONS);
   instr->len = htons(sizeof(struct ofp_instruction_actions) + numPorts * sizeof(struct ofp_action_output));
   for (int i = 0; i < numPorts; i++) {
      struct ofp_action_output *act = (void *) (buf + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions) + i *sizeof(struct ofp_action_output));
      act->type = OFPAT_OUTPUT;
      act->len= htons(sizeof(struct ofp_action_output));
      act->port = htonl(portNums[i]);
      act->max_len = OFPCML_MAX;
   }

   int loc = OFP_ETH_ALEN + 2 + sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions) + numPorts * sizeof(struct ofp_action_output);
   struct ofp_instruction_goto_table *instr2 = (void *) (buf + loc);
   instr2->type = ntohs(OFPIT_GOTO_TABLE);
   instr2->len = htons(sizeof(struct ofp_instruction_goto_table));
   instr2->table_id = 1;

   sendPacketToSocket(socketNum, buf, sizeof(buf));
}

void sendFlowModShortestUnicast(int socketNum, uint32_t *portNums, int numPorts, uint8_t hw_addr[OFP_ETH_ALEN]) {
   unsigned char buf[sizeof(struct ofp_flow_mod) + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_instruction_actions) + numPorts * sizeof(struct ofp_action_output) + sizeof(struct ofp_instruction_goto_table)];
   memset(buf, 0, sizeof(buf));

   struct ofp_flow_mod *flow = (void *)buf;
   flow->header.version = 0x4;
   flow->header.type = OFPT_FLOW_MOD;
   flow->header.length = htons(sizeof(buf));
   flow->header.xid = 0;
   flow->cookie = 0xf;
   flow->priority = htons(OFP_DEFAULT_PRIORITY);
   flow->table_id = 0;
   flow->command = OFPFC_MODIFY;
   flow->idle_timeout = ntohs(0);
   flow->hard_timeout = ntohs(0);
   flow->buffer_id = OFP_NO_BUFFER;
   flow->out_port = htonl(OFPP_ANY);
   flow->out_group = htonl(OFPG_ANY);
   flow->flags = htons(OFPFF_SEND_FLOW_REM);

   flow->match.type = ntohs(OFPMT_OXM);
   flow->match.length = htons(sizeof(struct ofp_match) + OFP_ETH_ALEN);
   uint16_t *temp2 = (void *) (buf + sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match) + sizeof(uint32_t));
   temp2[0]= htonl(OXM_OF_ETH_DST);
   temp2[1] = htonl(OXM_OF_ETH_DST)>>16;
   uint8_t *addr = (void *)&temp2[2];
   for (int i = 0; i < OFP_ETH_ALEN; i++) {
      addr[i] = hw_addr[i];
   }

   //flow->match.oxm_fields = OXM_OF_ETH_DST;
   struct ofp_instruction_actions *instr = (void *)(buf + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_flow_mod));
   instr->type = ntohs(OFPIT_APPLY_ACTIONS);
   instr->len = htons(sizeof(struct ofp_instruction_actions) + numPorts * sizeof(struct ofp_action_output));
   for (int i = 0; i < numPorts; i++) {
      struct ofp_action_output *act = (void *) (buf + OFP_ETH_ALEN  + 2+ sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions) + i *sizeof(struct ofp_action_output));
      act->type = OFPAT_OUTPUT;
      act->len= htons(sizeof(struct ofp_action_output));
      act->port = htonl(portNums[i]);
      act->max_len = OFPCML_MAX;
   }

   int loc = OFP_ETH_ALEN + 2 + sizeof(struct ofp_flow_mod) + sizeof(struct ofp_instruction_actions) + numPorts * sizeof(struct ofp_action_output);
   struct ofp_instruction_goto_table *instr2 = (void *) (buf + loc);
   instr2->type = ntohs(OFPIT_GOTO_TABLE);
   instr2->len = htons(sizeof(struct ofp_instruction_goto_table));
   instr2->table_id = 1;

   sendPacketToSocket(socketNum, buf, sizeof(buf));
}

void sendFlowModDeleteAll(int socketNum) {
   unsigned char buf[sizeof(struct ofp_flow_mod)];

   memset(buf, 0, sizeof(buf));
   struct ofp_flow_mod *flow = (void *)buf;
   flow->header.version = 0x4;
   flow->header.type = OFPT_FLOW_MOD;
   flow->header.length = htons(sizeof(buf));
   flow->header.xid = 0;
   flow->cookie = 0xf;
   flow->priority = OFP_DEFAULT_PRIORITY;
   flow->table_id = OFPTT_ALL;
   flow->command = OFPFC_DELETE;
   flow->idle_timeout = ntohs(0);
   flow->hard_timeout = ntohs(0);
   flow->buffer_id = OFP_NO_BUFFER;
   flow->out_port = OFPP_ANY;
   flow->out_group = OFPG_ANY;
   flow->flags = htons(OFPFF_SEND_FLOW_REM);

   flow->match.type = ntohs(OFPMT_OXM);
   flow->match.length = htons(sizeof(struct ofp_match) - 4);

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
      newPort->isConnectToSwitch = 0;
      newPort->connectedSwitchId = -1;
      newPort->hasBeenAdded = 0;
      temp->portList = newPort;
      temp->numPorts++;
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
      newPort->isConnectToSwitch = 0;
      newPort->connectedSwitchId = -1;
      newPort->hasBeenAdded = 0;
      temp->portList = newPort;
      temp->numPorts++;
      memset(newPort->hw_addr, 0, OFP_ETH_ALEN);
   }
   pthread_mutex_unlock(&networkGraphMutex);
}

void addSwitchToList(long switchId, int socketNum) {
   pthread_mutex_lock(&networkGraphMutex);
   switchUp *newSwitch = (switchUp *) calloc(sizeof(switchUp), 1);
   newSwitch->next = globalSwitchList;
   newSwitch->portList = NULL;
   newSwitch->switchId = switchId;
   newSwitch->numPorts = 0;
   newSwitch->socketNum = socketNum;
   globalSwitchList = newSwitch;
   pthread_mutex_unlock(&networkGraphMutex);
}

treeConstruct findMinHopLen(long fromSwitch, long toSwitch, long prevSwitch) {
   treeConstruct *results = NULL;
   switchUp *temp = globalSwitchList;
   treeConstruct ret;
   if (fromSwitch == toSwitch) {
      ret.fromSwitch = fromSwitch;
      ret.toSwitch = 1;
      return ret;
   }
   while (temp != NULL && temp->switchId != fromSwitch) {
      temp = temp->next;
   }
   if (temp != NULL) {
      portUp *iter = temp->portList;
      while (iter != NULL) {
         if (iter->isConnectToSwitch) {
            if (iter->connectedSwitchId != prevSwitch) {
               treeConstruct *resIter = results;
               if (resIter == NULL) {
                  results = (treeConstruct *) calloc(sizeof(treeConstruct), 1);
                  ret = findMinHopLen(iter->connectedSwitchId, toSwitch, fromSwitch);
                  //printf("------\n");
                  //printf("ret fromSwitch %ld toSwitch %ld prev %ld = %ld %ld\n", fromSwitch, toSwitch, prevSwitch, ret.fromSwitch, ret.toSwitch);

                  if (ret.fromSwitch == -1) {
                     results->fromSwitch = -1;
                     results->toSwitch =50000;
                  }
                  else {
                     results->fromSwitch = iter->portNum;
                     results->toSwitch = 1 + ret.toSwitch;
                  }
                  results->next = NULL;
               }
               else {
                  while (resIter->next != NULL) {
                     resIter = resIter->next;
                  }
                  resIter->next = (treeConstruct *) calloc(sizeof(treeConstruct), 1);
                  ret = findMinHopLen(iter->connectedSwitchId, toSwitch, fromSwitch);
                  //printf("ret fromSwitch %ld toSwitch %ld prev %ld = %ld %ld\n", fromSwitch, toSwitch, prevSwitch, ret.fromSwitch, ret.toSwitch);

                  if (ret.fromSwitch == -1) {
                     resIter->next->fromSwitch = -1;
                     resIter->next->toSwitch =50000;
                  }
                  else {
                     resIter->next->fromSwitch = iter->portNum;
                     resIter->next->toSwitch = 1 + ret.toSwitch;
                  }
                  resIter->next->next = NULL;
               }

            }
            else {
               treeConstruct *resIter = results;
               if (resIter == NULL) {
                  results = (treeConstruct *) calloc(sizeof(treeConstruct), 1);
                  results->fromSwitch = iter->portNum;
                  results->toSwitch = 50000;
                  results->next = NULL;
               }
               else {
                  while (resIter->next != NULL) {
                     resIter = resIter->next;
                  }
                  resIter->next = (treeConstruct *) calloc(sizeof(treeConstruct), 1);
                  resIter->next->fromSwitch = iter->portNum;
                  resIter->next->toSwitch = 50000;
                  resIter->next->next = NULL;

               }
            }

         }
         iter = iter->next;
      }

      int lowest = 500000;
      long port = -1;
      treeConstruct *resIter = results;

      while (resIter != NULL) {
         //printf("ret fromSwitch %ld toSwitch %ld prev %ld = %ld %ld (%ld %d)\n", fromSwitch, toSwitch, prevSwitch, resIter->fromSwitch, resIter->toSwitch, port, lowest);
         if (resIter->toSwitch < lowest && resIter->toSwitch != -1) {
            lowest = resIter->toSwitch;
            port = resIter->fromSwitch;
         }
         results = resIter;
         resIter = resIter->next;
         free(results);
      }
      ret.fromSwitch = port;
      ret.toSwitch = lowest;
      return ret;
   }
   ret.fromSwitch = fromSwitch;
   ret.toSwitch = -1;
   return ret;
}

void addSwitchConnection(long switchId, int portId, long connectedSwitchId) {
   pthread_mutex_lock(&networkGraphMutex);
   switchUp *temp = globalSwitchList;
   while (temp != NULL && temp->switchId != switchId) {
      temp = temp->next;
   }
   if (temp != NULL) {
      portUp *temp2 = temp->portList;
      while (temp2 != NULL && temp2->portNum != portId) {
         temp2 = temp2->next;
      }
      if (temp2 != NULL) {
         temp2->isConnectToSwitch = 1;
         temp2->connectedSwitchId = connectedSwitchId;
      }
   }
   pthread_mutex_unlock(&networkGraphMutex);
}

int checkInTree(treeConstruct *head, long fromSwitch, long toSwitch) {
   treeConstruct *temp = head;
   while (temp != NULL) {
      if (temp->fromSwitch == fromSwitch) {
         if (temp->toSwitch == toSwitch) {
            return 1;
         }
      }
      temp = temp->next;
   }

   if (inTree(head, fromSwitch) == 1 && inTree(head, toSwitch)) {
      return 1;
   }


   return 0;
}

int inTree(treeConstruct *head, long id) {
   treeConstruct *temp = head;
   while (temp != NULL) {
      if (temp->fromSwitch == id || temp->toSwitch == id) {
         return 1;
      }
      temp = temp->next;
   }
   return 0;
}

treeConstruct *addToTree(treeConstruct *head, long fromSwitch, long toSwitch, long portNum) {
      treeConstruct *temp = (treeConstruct *) calloc(sizeof(treeConstruct), 1);
      temp->fromSwitch = fromSwitch;
      temp->toSwitch = toSwitch;
      temp->next = head;
      //Indicate port has been used
      switchUp *iter = globalSwitchList;
      while (iter != NULL && iter->switchId != fromSwitch) {
         iter = iter->next;
      }
      if (iter != NULL) {
         portUp *portIter = iter->portList;
         while (portIter != NULL && portIter->portNum != portNum) {
            portIter = portIter->next;
         }
         if (portIter != NULL) {
            portIter->hasBeenAdded = 1;
         }
      }
      //indicate reciprocal has been used
      switchUp *iter2 = globalSwitchList;
      while (iter2 != NULL && iter2->switchId != toSwitch) {
         iter2 = iter2->next;
      }
      if (iter2 != NULL) {
         portUp *portIter2 = iter2->portList;
         while (portIter2 != NULL) {
            if (portIter2->isConnectToSwitch) {
               if (portIter2->connectedSwitchId == fromSwitch) {
                  portIter2->hasBeenAdded = 1;
                  return temp;
               }
            }
            portIter2 = portIter2->next;
         }
      }

      return temp;
}

idList *getListOfConnect(treeConstruct *head, long fromSwitch) {
   treeConstruct *temp = head;
   idList *list = NULL;
   while (temp != NULL) {
      if (temp->fromSwitch == fromSwitch) {
         if (list == NULL) {
            list = (idList *) calloc(sizeof(idList), 1);
            list->id = temp->toSwitch;
            list->next = NULL;
         }
         else {
            idList *temp2 = list;
            while (temp2->next != NULL) {
               temp2 = temp2->next;
            }
            temp2->next = (idList *) calloc(sizeof(idList), 1);
            temp2->next->id = temp->toSwitch;
            temp2->next->next = NULL;
         }
      }
      temp = temp->next;
   }
   return list;
}

void clearTree(treeConstruct *head) {
   while (head != NULL) {
      treeConstruct *temp = head->next;
      free(head);
      head = temp;
   }
   switchUp *iter = globalSwitchList;
   while (iter != NULL) {
      portUp *ports = iter->portList;
      while (ports != NULL) {
         ports->hasBeenAdded = 0;
         ports = ports->next;
      }
      iter = iter->next;
   }
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
         if (state == PORT_STAT_DOWN || state == PORT_SUPPRESSED) {
            if (tempP->isConnectToSwitch) {
               tempP->isConnectToSwitch = 0;
            }
         }
         else if (state == PORT_SENDING) {
            sendProbePacket(temp->socketNum, temp->switchId, tempP->portNum, tempP->hw_addr);
         }
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
            tempP->port_addr[i] = p.hw_addr[i];
         }
      }
   }
   pthread_mutex_unlock(&networkGraphMutex);
}

void addPortHwAddrInfo(long switchId, int portNum, uint8_t hw_addr[OFP_ETH_ALEN]) {
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
         for (int i = 0; i < OFP_ETH_ALEN; i++) {
            tempP->hw_addr[i] = hw_addr[i];
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
      temp->numPorts--;
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
   pthread_mutex_lock(&networkGraphMutex);
   wasUpdated++;
   pthread_cond_signal(&cond);
   pthread_mutex_unlock(&networkGraphMutex);
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
      printf("\tcookie = %lx\n", in->cookie);
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
      //analyzePacketP(in->data);
   }
   else if (type == OFPT_FEATURES_REPLY) {
      struct ofp_switch_features *features = (struct ofp_switch_features *) packet;
      printf("---Features Reply---\n");
      printf("\tdata path id = %x\n", ntohl(features->datapath_id));
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
      pthread_mutex_unlock(&printMutex);
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
   printf("\t\tnumber packets rx = %u\n", ntohl(stats->rx_packets));
   printf("\t\tnumber packets tx = %u\n", ntohl(stats->tx_packets));
   printf("\t\tnumber bytes rx = %u\n", ntohl(stats->rx_bytes));
   printf("\t\tnumber bytes tx = %u\n", ntohl(stats->tx_bytes));
   printf("\t\tnumber packets dropped rx = %u\n", ntohl(stats->rx_dropped));
   printf("\t\tnumber packets dropped tx = %u\n", ntohl(stats->tx_dropped));
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
      printf("\thasBeenAdded = %d\n", temp->hasBeenAdded);
      printf("\thardware addr = ");
      printf("%x", temp->hw_addr[0]);
      int i = 0;
      for (i = 1; i < OFP_ETH_ALEN; i++) {
         printf(":%x", temp->hw_addr[i]);
      }
      printf("\n");
      printf("\tport addr = ");
      printf("%x", temp->port_addr[0]);
      for (i = 1; i < OFP_ETH_ALEN; i++) {
         printf(":%x", temp->port_addr[i]);
      }
      printf("\n");
      if (temp->isConnectToSwitch) {
         printf("\t-------Connected to Switch------ %ld\n", temp->connectedSwitchId);
      }
      temp = temp->next;
   }
}
