#include "trace.h"

/*int main(int args, char **argv) {
   char errBuf[PCAP_ERRBUF_SIZE];
   int totalPacketCount = 0;
   struct pcap_pkthdr header;
   const unsigned char *packet;

   if (args > 2 || args <= 1) {
      fprintf(stderr, "Need to specify a file\n");
      exit(-1);
   }

   //Opens a pcap object to navigate the pcap file
   pcap_t *pcap = pcap_open_offline(argv[1], errBuf);

   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_offline failed to open\n");
      exit(-1);
   }

   //Gets the next packet from the pcap file; 
   while ((packet = pcap_next(pcap, &header)) != NULL) {
      totalPacketCount++; 
      printf("Packet number: %d  ", totalPacketCount);
      
      analyzePacket(pcap, &header, packet);
   }
   return 0;
}*/

void analyzePacket(unsigned char *pcap, const struct pcap_pkthdr *header,
      const unsigned char *packet) {
   int i = 0;
   ethernetInfo *ethernet = (ethernetInfo *) (packet);
   printf("Packet Len: %d\n\n", header->len); 
   printf("\tEthernet Header\n");

   printf("\t\tDest MAC: %x", ethernet->mac_dest_host[0]);
   for (i = 1; i < ETHER_ADDR_LEN; i++) {
      printf(":%x", ethernet->mac_dest_host[i]);
   }
   printf("\n");
   printf("\t\tSource MAC: %x", ethernet->mac_src_host[0]);
   for (i = 1; i < ETHER_ADDR_LEN; i++) {
      printf(":%x", ethernet->mac_src_host[i]);
   }
   printf("\n");
   if (ethernet->ether_type == ETHER_ARP_TYPE) {
      printf("\t\tType: ARP\n\n");
      analyzeARP(packet + ETHER_HEADER_SIZE);
   }
   else if (ethernet->ether_type == ETHER_IP_TYPE) {
      printf("\t\tType: IP\n\n");
      analyzeIP(packet + ETHER_HEADER_SIZE);
   }
   else {
      fprintf(stderr, "UNKNOWN TYPE\n");
   } 
   printf("\n");
}

void analyzeARP(const unsigned char *packet) {
   arpInfo *arp = (arpInfo *) (packet);
   int i = 0;

   printf("\tARP header\n");
   
   if (ntohs(arp->opcode) == ARP_REQUEST) {
      printf("\t\tOpcode: Request\n");
   }
   else if (ntohs(arp->opcode) == ARP_REPLY) {
      printf("\t\tOpcode: Reply\n");
   }
   else {
      fprintf(stderr, "INVALID ARP CODE\n");
   }
   printf("\t\tSender MAC: %x", arp->mac_sender_addr[0]);
   for (i = 1; i < ETHER_ADDR_LEN; i++) {
      printf(":%x", arp->mac_sender_addr[i]);
   }
   printf("\n");
   printf("\t\tSender IP: %d", arp->ip_sender_addr[0]);
   for (i = 1; i < IP_ADDR_LEN; i++) {
      printf(".%d", arp->ip_sender_addr[i]);
   }
   printf("\n");  
   printf("\t\tTarget MAC: %x", arp->mac_dest_addr[0]);
   for (i = 1; i < ETHER_ADDR_LEN; i++) {
      printf(":%x", arp->mac_dest_addr[i]);
   }
   printf("\n");
   printf("\t\tTarget IP: %d", arp->ip_dest_addr[0]);
   for (i = 1; i < IP_ADDR_LEN; i++) {
      printf(".%d", arp->ip_dest_addr[i]);
   }
   printf("\n");
}

void analyzeIP(const unsigned char *packet) {
   ipInfo *ip = (ipInfo *) (packet);
   int i = 0;
   int protocol = 0;
   tcpPseudoHeader *tcp_pseudo;
   tcp_pseudo = (tcpPseudoHeader *) calloc(1,sizeof(tcpPseudoHeader));
   
   printf("\tIP Header\n");
   printf("\t\tIP Version: %d\n", ip->ip_version>>4);
   printf("\t\tHeader Len (bytes): %d\n", (ip->ip_version & 0x0f) * 4);
   printf("\t\tTOS subfields:\n");
   printf("\t\t\tDiffserv bits: %d\n", ip->ip_type>>2);
   printf("\t\t\tECN bits: %d\n", ip->ip_type & 0x03);
   printf("\t\tTTL: %d\n", ip->ip_time_live);
   
   printf("\t\tProtocol: ");
   if (ip->ip_proto == 1) {
      printf("ICMP\n");   
      protocol = ICMP;
   }
   else if (ip->ip_proto == 6) {
      printf("TCP\n");
      protocol = TCP;
      tcp_pseudo->ip_proto = ip->ip_proto;
   }
   else if (ip->ip_proto == 17) {
      printf("UDP\n");
      protocol = UDP;
   }
   else {
      printf("Unknown\n");
   }

   printf("\t\tChecksum: ");
   if (!in_cksum((unsigned short *)packet, (ip->ip_version & 0x0f) *4)) {
      printf("Correct (0x%04x)\n", ntohs(ip->ip_checksum));
   }
   else {
      printf("Incorrect (0x%04x)\n", ntohs(ip->ip_checksum));
   }
   printf("\t\tSender IP: %d", ip->ip_src_addr[0]);
   tcp_pseudo->ip_src_addr[0] = ip->ip_src_addr[0];
   for (i = 1; i < IP_ADDR_LEN; i++) {
      printf(".%d", ip->ip_src_addr[i]);
      tcp_pseudo->ip_src_addr[i] = ip->ip_src_addr[0];
   }
   printf("\n"); 
   printf("\t\tDest IP: %d", ip->ip_dest_addr[0]);
   tcp_pseudo->ip_dest_addr[0] = ip->ip_dest_addr[0];
   for (i = 1; i < IP_ADDR_LEN; i++) {
      tcp_pseudo->ip_dest_addr[i] = ip->ip_dest_addr[i];
      printf(".%d", ip->ip_dest_addr[i]);
   }
   printf("\n"); 

   if (protocol == ICMP) {
      printf("\n");
      analyzeICMP(packet + (ip->ip_version & 0x0f) * 4);
   }
   else if (protocol == TCP) {
      printf("\n");
      analyzeTCP(packet + (ip->ip_version & 0x0f) * 4, ip);
   }
   else if (protocol == UDP) {
      printf("\n");
      analyzeUDP(packet + (ip->ip_version & 0x0f) * 4);
   }
   else {
      fprintf(stderr, "Unknown Protocol\n");
   }
}

void analyzeICMP(const unsigned char *packet) {
   icmpInfo *icmp = (icmpInfo *) (packet); 

   printf("\tICMP Header\n");
   printf("\t\tType: ");
   if (icmp->icmp_type == ICMP_REQUEST) {
      printf("Request\n");      
   }
   else if (icmp->icmp_type == ICMP_REPLY) {
      printf("Reply\n");
   }
   else {
      printf("%d\n", icmp->icmp_type);
   }
}

void analyzeTCP(const unsigned char *packet, ipInfo *ip) {
   tcpInfo *tcp = (tcpInfo *) (packet);
   uint16_t checksum = ntohs(tcp->tcp_checksum);
   uint16_t checksumRet;
   char checkSplit[2];

   printf("\tTCP Header\n");
   printf("\t\tSource Port: ");
   if (ntohs(tcp->tcp_src_port) == 80) {
      printf("HTTP\n");
   }
   else {
      printf("%d\n", ntohs(tcp->tcp_src_port));
   }
   printf("\t\tDest Port: ");
   if (ntohs(tcp->tcp_dest_port) == 80) {
      printf("HTTP\n");
   }
   else if (ntohs(tcp->tcp_dest_port) == 23) {
      printf("Telnet\n");
   }
   else if (ntohs(tcp->tcp_dest_port) == 21) {
      printf("FTP\n");
   }
   else if (ntohs(tcp->tcp_dest_port) == 110) {
      printf("POP3\n");
   }
   else if (ntohs(tcp->tcp_dest_port) == 25) {
      printf("SMTP\n");
   }
   else {
      printf("%d\n", ntohs(tcp->tcp_dest_port));
   }
   printf("\t\tSequence Number: %u\n", ntohl(tcp->tcp_seq_num));
   printf("\t\tACK Number: %u\n", ntohl(tcp->tcp_ack_num));
   printf("\t\tData Offset (bytes): %d\n", ((tcp->tcp_off & 0xf0) >>4) * 4);
   printf("\t\tSYN Flag: ");
   if ((tcp->tcp_flags & 0x02)) {
     printf("Yes\n");
   }
   else {
      printf("No\n");
   }
   printf("\t\tRST Flag: ");
   if ((tcp->tcp_flags & 0x04)) {
      printf("Yes\n");
   }
   else {
      printf("No\n");
   }
   printf("\t\tFIN Flag: ");
   if ((tcp->tcp_flags & 0x01)) {
      printf("Yes\n");
   }
   else {
      printf("No\n");
   }
   printf("\t\tACK Flag: ");
   if ((tcp->tcp_flags & 0x10)) {
      printf("Yes\n");
   }
   else {
      printf("No\n");
   }
   printf("\t\tWindow Size: %d\n", ntohs(tcp->tcp_window));
   //TCP CHECKSUM NEEDS TO BE FIXED!
   tcp->tcp_checksum = 0x0000;
   if ((checksumRet = tcpChecksum(tcp, ip) != checksum)) {
      printf("\t\tChecksum: Incorrect (0x%02x", ntohs(checksum & 0xff00));
      printf("%02x)\n", checksum & 0x00ff);
   }
   else {
      memcpy(checkSplit, &checksum, sizeof(checksum));
      printf("\t\tChecksum: Correct (0x%02x", checkSplit[1] & 0x00ff);
      printf("%02x)\n", checkSplit[0] & 0x00ff);
   }
}

void analyzeUDP(const unsigned char *packet) {
   udpInfo *udp = (udpInfo *) (packet);
   
   printf("\tUDP Header\n");
   if (ntohs(udp->udp_src_port) == 53) {
      printf("\t\tSource Port: DNS\n");
   }
   else {
      printf("\t\tSource Port: %d\n", ntohs(udp->udp_src_port));
   }
   if (ntohs(udp->udp_dest_port) == 53) {
      printf("\t\tDest Port: DNS\n");   
   }
   else {
      printf("\t\tDest Port: %d\n", ntohs(udp->udp_dest_port));   
   }
}

uint16_t tcpChecksum(tcpInfo *tcp, ipInfo *ip) {
   uint16_t totLen = ntohs(ip->ip_len); 
   uint32_t tcpOptLen = ((tcp->tcp_off & 0xf0) >>4) * 4; //-20?
   uint32_t ipHeadLen = (ip->ip_version & 0x0f) * 4;
   uint32_t tcpDataLen = totLen - tcpOptLen - ipHeadLen;
   int i = 0;
   if ((int32_t)tcpDataLen < 0) {
      return 0x0000;
   }
   tcpPseudoHeader pseudoHead;
   for(i = 0; i < IP_ADDR_LEN; i++) {
      pseudoHead.ip_src_addr[i] = ip->ip_src_addr[i]; 
   }
   for(i = 0; i < IP_ADDR_LEN; i++) {
      pseudoHead.ip_dest_addr[i] = ip->ip_dest_addr[i]; 
   }
   pseudoHead.reserved = 0;
   pseudoHead.ip_proto = 6;
   pseudoHead.length = htons(sizeof(tcpInfo) + tcpOptLen - 20 + tcpDataLen); 

   uint32_t totTCPLen = sizeof(tcpPseudoHeader) + sizeof(tcpInfo) + tcpDataLen + tcpOptLen - 20;
   uint16_t *tcpPtr = (uint16_t *)calloc(totTCPLen, 2);
   memcpy((unsigned char *) tcpPtr, &pseudoHead, sizeof(tcpPseudoHeader));
   memcpy((unsigned char *) tcpPtr + sizeof(tcpPseudoHeader),
      (unsigned char *)tcp, sizeof(tcpInfo));
   memcpy((unsigned char *) tcpPtr + sizeof(tcpPseudoHeader) + sizeof(tcpInfo), 
      (unsigned char *) ip + ipHeadLen + sizeof(tcpInfo), tcpOptLen);
   memcpy((unsigned char *) tcpPtr + sizeof(tcpPseudoHeader) + sizeof(tcpInfo) +tcpOptLen - 20, 
      (unsigned char *) tcp + tcpOptLen, tcpDataLen);
   return ntohs(in_cksum(tcpPtr, totTCPLen));

}


