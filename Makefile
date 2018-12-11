all:	cap

cap:	captureme.c Makefile
	$(CC) $(COPT) -o cap captureme.c /usr/include/libnet/libnet-functions.h -lpcap $(LOPT)
	$(CC) $(COPT) -o analysecap decodeLBARD.c $(LOPT)
	
