#include "pingSpoof.h"

int STATE = START;
char *ip_addr;
char *mac_addr;


int main(int args, char** argv) {
   if (args != 3) {
      printf("Usage: ./ping_spoof <spoofed-mac-address> <spoofed-ip-address>\n");
      return 1;
   }

   ip_addr = argv[2];
   mac_addr = argv[1];

   printf("MAC = %s\n", argv[1]);
   printf("IP = %s\n", argv[2]);

   char *dev, errbuf[PCAP_ERRBUF_SIZE];
   bpf_u_int32 mask;
   bpf_u_int32 net;

   dev = pcap_lookupdev(errbuf);
   if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      return 2;
   }

   printf("Using Device %s to listen\n", dev);

   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
      fprintf(stderr, "Can't get netmask for device %s\n", dev);
      net = 0;
      mask = 0;
   }

   pcap_t *handle;
   handle = pcap_open_live(dev, BUFF_SIZE, 1, 1000, errbuf);

   if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
      return 2;
   }

   struct bpf_program fp;
   char filter_exp[] = "arp";


   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return 2;
   }

   if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return(2);
   }

   int err = pcap_loop(handle, 1, packetController, (unsigned char *) argv[2]);
   while (STATE != RESPOND_ARP) {
      if (err != 0) {
         fprintf(stderr, "%s\n", "Error on pcap_loop");
         return -1;
      }
      err = pcap_loop(handle, 1, packetController, (unsigned char *) argv[2]);
   }
   if (err != 0) {
      fprintf(stderr, "%s\n", "Error on pcap_loop");
   }

   pcap_close(handle);
   return 0;
}

void packetController(unsigned char *pcap, const struct pcap_pkthdr *header, const unsigned char *packet) {
   if (STATE == START) {
      arpInfo *arp = (arpInfo *) (packet + ETHER_HEADER_SIZE);
      printf("\t\tTarget IP: %d", arp->ip_dest_addr[0]);
      for (int i = 1; i < IP_ADDR_LEN; i++) {
         printf(".%d", arp->ip_dest_addr[i]);
      }
      printf("\n");
      int ret =compareIP(pcap, &(arp->ip_dest_addr[0]));
      if (ret != 0) {
         printf("RESPOND STATE\n\n");
         STATE = RESPOND_ARP;
         int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
         if (s == -1) {
            perror("socket error");
         }
         unsigned char *packetToSend = contructPacket(pcap, arp);
         analyzePacket((pcap_t *) pcap, header, packetToSend);
         struct sockaddr_in sock_addr;
         memset(&sock_addr, 0, sizeof(struct sockaddr_in));
         sock_addr.sin_family = AF_INET;
         sock_addr.sin_port = htons(0);
         printf("%d\n", inet_addr(ip_addr));
         unsigned int addr = 0;
         memcpy(&addr, arp->ip_sender_addr, 4);
         sock_addr.sin_addr.s_addr = addr;

         int retVal = send(s, packetToSend, sizeof(ethernetInfo) + sizeof(arpInfo));
         if (retVal < 0) {
            perror("ERROR SENDING SOCKET");
         }
         free(packetToSend);
      }
   }
}

int compareIP(unsigned char *ip, unsigned char *ipByte) {
   int matched = 1;
   char *temp = malloc(strlen((char *) ip) + 1);
   int count = 0;
   char *begin = temp;
   memset(temp, 0, strlen((char *) ip) + 1);
   memcpy(temp, ip, strlen((char *) ip));

   temp = strtok(temp, ".");
   while (temp != NULL) {
      if (atoi(temp) != ipByte[count]) {
         matched = 0;
      }
      temp = strtok(NULL, ".");
      count++;
   }

   free(begin);

   return matched;
}

unsigned char *contructPacket(unsigned char *pcap, arpInfo *arp) {
   unsigned char *outPacket = malloc(PACKET_SIZE);

   memset(outPacket, 0, PACKET_SIZE);

   ethernetInfo *e = (ethernetInfo *) outPacket;
   e->mac_dest_host[0] = arp->mac_sender_addr[0];
   e->mac_dest_host[1] = arp->mac_sender_addr[1];
   e->mac_dest_host[2] = arp->mac_sender_addr[2];
   e->mac_dest_host[3] = arp->mac_sender_addr[3];
   e->mac_dest_host[4] = arp->mac_sender_addr[4];
   e->mac_dest_host[5] = arp->mac_sender_addr[5];

   unsigned char mac[6];
   sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

   e->mac_src_host[0] = mac[0];
   e->mac_src_host[1] = mac[1];
   e->mac_src_host[2] = mac[2];
   e->mac_src_host[3] = mac[3];
   e->mac_src_host[4] = mac[4];
   e->mac_src_host[5] = mac[5];

   e->ether_type = ETHER_ARP_TYPE;

   arpInfo *a = (arpInfo *) (outPacket + ETHER_HEADER_SIZE);
   a->opcode = htons(ARP_REPLY);

   a->mac_sender_addr[0] = mac[0];
   a->mac_sender_addr[1] = mac[1];
   a->mac_sender_addr[2] = mac[2];
   a->mac_sender_addr[3] = mac[3];
   a->mac_sender_addr[4] = mac[4];
   a->mac_sender_addr[5] = mac[5];

   int count = 0;
   char *temp = malloc(strlen((char *) ip_addr) + 1);
   char *begin = temp;
   memset(temp, 0, strlen((char *) ip_addr) + 1);
   memcpy(temp, ip_addr, strlen((char *) ip_addr));

   temp = strtok(temp, ".");
   while (temp != NULL) {
      a->ip_sender_addr[count] = atoi(temp);
      temp = strtok(NULL, ".");
      count++;
   }
   free(begin);

   a->mac_dest_addr[0] = arp->mac_sender_addr[0];
   a->mac_dest_addr[1] = arp->mac_sender_addr[1];
   a->mac_dest_addr[2] = arp->mac_sender_addr[2];
   a->mac_dest_addr[3] = arp->mac_sender_addr[3];
   a->mac_dest_addr[4] = arp->mac_sender_addr[4];
   a->mac_dest_addr[5] = arp->mac_sender_addr[5];

   a->ip_dest_addr[0] = arp->ip_sender_addr[0];
   a->ip_dest_addr[1] = arp->ip_sender_addr[1];
   a->ip_dest_addr[2] = arp->ip_sender_addr[2];
   a->ip_dest_addr[3] = arp->ip_sender_addr[3];

   a->hw_type = 1;
   a->p_type = 0x0800;
   a->hw_len = 6;
   a->p_len = 4;


   return outPacket;


}
