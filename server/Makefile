COPT=	-Wall -g

all:	cap

cap:	svrcapture.c message_handlers.c Makefile
	$(CC) $(COPT) -o svrCap svrcapture.c message_handlers.c parseLBARD.c $(LOPT)
	
