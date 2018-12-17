all:	cap

cap:	captureme.c Makefile
	$(CC) $(COPT) -o capture captureme.c -lpcap $(LOPT)
	#$(CC) $(COPT) -o decodeCapture decodeLBARD.c $(LOPT)
	
