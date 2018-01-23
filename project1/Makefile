compile : pingSpoof.c
	gcc -Wall -Werror -o ping_spoof pingSpoof.c trace.c checksum.c -lpcap 

push : 
	git status
	git add .
	git commit -m MESSAGE
	git push

