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
   printf("Starting Controller on port %d\n", portNum);
   int serverSocketNum = startTCPSocket();
   printf("\tCreated a socket on port %d with Socket number %d\n", portNum, serverSocketNum);

   int clientSocketNum = acceptTCP(serverSocketNum);
   printf("\tAccepted connection with Socket Number %d\n", clientSocketNum);
   unsigned char *packet = readPacketFromSocket(clientSocketNum);
   if (packet == NULL) {
      printf("Packet NULL\n");
   }
   return 0;
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
   //unsigned char *packet;
   //uint16_t packetSize;
   unsigned char buf[2048];
   int msgLen = 0;
   memset(buf, 0, 2048);
   if ((msgLen = recv(socketNumber, &buf, 2048, MSG_WAITALL)) < 0) {
      perror("Recv Call Failure");
      exit(-1);
   }
   return NULL;

}
