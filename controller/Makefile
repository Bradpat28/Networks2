compile : controller.c
	gcc -Wall -Werror -o controller controller.c checksum.c smartalloc.c trace.c -lpcap -pthread
	

clean :
	rm -rf ./controller
