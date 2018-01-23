#include "pingSpoof.h"




int main(int args, char** argv) {
   if (args != 3) {
      printf("Usage: ./ping_spoof <spoofed-mac-address> <spoofed-ip-address>\n");
      return 1;
   }

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

   //const u_char *packet;
   //struct pcap_pkthdr header;

   int err = pcap_loop(handle, 1, analyzePacket, NULL);

   if (err != 0) {
      fprintf(stderr, "%s\n", "Error on pcap_loop");
   }

   pcap_close(handle);
   return 0;





   return 0;

}




