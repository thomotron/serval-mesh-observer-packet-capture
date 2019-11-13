COPT=	-Wall -g -std=gnu99

all:	capture

capture:	captureme.c Makefile
	@echo $(CC) $(COPT) -o capture captureme.c -lpcap -largp $(LOPT)
	$(CC) $(COPT) -o capture captureme.c -lpcap -largp $(LOPT)
	
