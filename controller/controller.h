#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>

#include "trace.h"
#include "smartalloc.h"
#include "checksum.h"


#define DEFAULT_OF_PORT 6653

int startController();
int startTCPSocket();
int acceptTCP(int serverSocketNum);
unsigned char *readPacketFromSocket(int socketNum);
