all:	cap

cap:	captureme.c Makefile
	$(CC) $(COPT) -o capture captureme.c -lpcap $(LOPT)
	$(CC) $(COPT) -o decodeLBARD decodeLBARD.c $(LOPT)
	$(CC) $(COPT) -o svrCapture svrCapture.c $(LOPT)
	
