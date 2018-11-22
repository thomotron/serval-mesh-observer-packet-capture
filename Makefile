all:	capture

capture:	captureme.c Makefile
	gcc -o capture captureme.c -lpcap
