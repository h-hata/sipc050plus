#include <netinet/in.h>
size_t RecvData(int socket,unsigned char *buff,size_t *len,int *cliaddr,int *cliport,int timer,int *ret);
size_t RecvDataMulti(int ,int,unsigned char *buff,size_t *len,int *cliaddr,int *cliport,int timer,int *ret);
size_t SendData(char *host,int port,unsigned char *sbuff,size_t slen);
size_t SendDataSocket(int s,char *host,int port,unsigned char *sbuff,size_t slen);
void ConvertIP4(int ,char *);
void InvertIP4(char *,int *);
