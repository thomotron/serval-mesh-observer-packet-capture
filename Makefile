all:	cap

cap:	captureme.c Makefile
	$(CC) $(COPT) -o cap captureme.c -lpcap  $(LIBS) $(LOPT)
	$(CC) $(COPT) -o analysecap decodeLBARD.c $(LOPT)
	
