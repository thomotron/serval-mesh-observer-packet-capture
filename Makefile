all:	cap

cap:	captureme.c Makefile
	gcc -o cap captureme.c -lpcap
