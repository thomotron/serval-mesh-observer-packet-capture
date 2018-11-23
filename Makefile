all:	cap

cap:	captureme.c Makefile
	$(CC) $(COPT) -o cap captureme.c -lpcap $(LOPT)
