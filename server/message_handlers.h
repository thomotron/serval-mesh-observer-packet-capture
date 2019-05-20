typedef int (*message_handler)(struct peer_state *,char *,
                               char *, char *,unsigned char *,int);  
extern message_handler message_handlers[257];

int message_parser_41(struct peer_state *,char *, char *, char *,unsigned char *,int);
int message_parser_42(struct peer_state *,char *, char *, char *,unsigned char *,int);
int message_parser_50(struct peer_state *,char *, char *, char *,unsigned char *,int);
int message_parser_4C(struct peer_state *,char *, char *, char *,unsigned char *,int);
int message_parser_47(struct peer_state *,char *, char *, char *,unsigned char *,int);
int message_parser_4D(struct peer_state *,char *, char *, char *,unsigned char *,int);
int message_parser_52(struct peer_state *,char *, char *, char *,unsigned char *,int);
int message_parser_53(struct peer_state *,char *, char *, char *,unsigned char *,int);
int message_parser_54(struct peer_state *,char *, char *, char *,unsigned char *,int);
#define message_parser_46 message_parser_41
#define message_parser_66 message_parser_41
#define message_parser_61 message_parser_41
#define message_parser_51 message_parser_50
#define message_parser_70 message_parser_50
#define message_parser_71 message_parser_50
