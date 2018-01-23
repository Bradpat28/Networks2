

typedef struct ethernetInfo {
   unsigned char mac_dest_host[ETHER_ADDR_LEN];
   unsigned char mac_src_host[ETHER_ADDR_LEN];
   uint16_t ether_type; 
} ethernetInfo;

typedef struct arpInfo {
   uint16_t hw_type;
   uint16_t p_type;
   unsigned char hw_len;
   unsigned char p_len;
   uint16_t opcode;
   unsigned char mac_sender_addr[ETHER_ADDR_LEN];
   unsigned char ip_sender_addr[IP_ADDR_LEN];
   unsigned char mac_dest_addr[ETHER_ADDR_LEN];
   unsigned char ip_dest_addr[IP_ADDR_LEN];
} arpInfo;

typedef struct ipInfo {
   unsigned char ip_version;
   unsigned char ip_type;
   uint16_t ip_len;
   uint16_t ip_id;
   uint16_t ip_offset;
   unsigned char ip_time_live;
   unsigned char ip_proto;
   uint16_t ip_checksum;
   unsigned char ip_src_addr[IP_ADDR_LEN];
   unsigned char ip_dest_addr[IP_ADDR_LEN];
} ipInfo;

typedef struct icmpInfo {
   unsigned char icmp_type;
   unsigned char icmp_code;
   uint16_t icmp_checksum;
} icmpInfo;

typedef struct tcpInfo {
   uint16_t tcp_src_port;
   uint16_t tcp_dest_port;
   unsigned int tcp_seq_num;
   unsigned int tcp_ack_num;
   unsigned char tcp_off;
   unsigned char tcp_flags;
   uint16_t tcp_window;
   uint16_t tcp_checksum;
   uint16_t tcp_urgent_ptr;
} tcpInfo;

typedef struct tcpPseudoHeader {
   unsigned char ip_src_addr[IP_ADDR_LEN];
   unsigned char ip_dest_addr[IP_ADDR_LEN];
   unsigned char reserved;
   unsigned char ip_proto;
   uint16_t length;
} tcpPseudoHeader;

typedef struct udpInfo {
   uint16_t udp_src_port;
   uint16_t udp_dest_port;
   uint16_t udp_length;
   uint16_t udp_checksum;
} udpInfo;






