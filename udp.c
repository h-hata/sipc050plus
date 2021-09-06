/***********************************************************************\

	SIP Server	

	Date		Ver		Author		MemoRandom
	Jul 3,2002	1.0		Hiroaki Hata	Created

	(C) 2002 All Copyrights reserved. 
*************************************************************************/
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <ctype.h>
#include <unistd.h>

#include "sip.h"
#include "udp.h"
#include "tls.h"

int	dump_flag=0;

static SSL *ssl=NULL;

static void dump_packet(void *ptr,int len)
{
	unsigned char	*ptr1,*ptr2;
	int	count1=0;
	int	count2=0;
	int	i,j,k;
	char	c;
	printf("Packet len = %d(0x%X)bytes\n",len,len);
	for(i=0;;i++){
		ptr1=ptr2=ptr+i*16 ;
		for(j=0;j<16;j++){
			printf("%02X",*ptr2++);
			if(j==7){
				printf(" - ");
			}else{
				printf(" ");
			}
			count1++;
			if(count1 >= len ) break;
		}
		k = 16 - j-1;
		for(j=0; j < k ; j++) printf("   ");
		if(k > 8 )            printf("  ");
		ptr2=ptr1;
		for(j=0;j<16;j++){
			if(isprint(*ptr2)){
                              c=*ptr2;
			} else{
                              c='.';
			}
			ptr2++;
			printf("%1c",c);
			if(j==7){
				printf(" ");
			}
			count2++;
			if(count2 >= len ) {printf("\n\n");return ;}
		}
		printf("\n");
	}
}
void TerminateTLS(void)
{
	if(ssl!=NULL){
		TLS_ClientShutdown();
	}
	ssl=NULL;
}
int InitializeTLS(char *cacert,char *host,int port)
{
	int ret;
	TLS_Init();
	ret=TLS_ClientSetup(cacert);
	if(ret<0){
		return SIP_E_ERROR-300;
	}
	ssl=TLS_Connect(host,port,&ret);
	if(ssl==NULL){
		return SIP_E_ERROR-310;
	}
	return SIP_E_OK;
}

int InitializeUDP(int port)
{

	int s;
	int n;
	struct sockaddr_in	myaddr_in;
	int	aslen;

	aslen=sizeof(struct sockaddr_in);
	memset((char *)&myaddr_in,0,aslen);
	myaddr_in.sin_family = AF_INET;
	myaddr_in.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr_in.sin_port = htons(port);
	/**********************************Socket生成*/
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if ( s <0 ) {
		syserr("socket");
	}
	n=bind(s,(struct sockaddr *)&myaddr_in,aslen);
	if(n<0){
		syserr("bind");
	}
	return s;	
}



size_t RecvData(int s,unsigned char *buff,size_t *len,int *cliaddr,int *cliport,int timer,int *reason)
{
	size_t n;
	struct timeval tv;
	fd_set	fdset;
	struct sockaddr_in	clientaddr_in;
	socklen_t	aslen;
	if(ssl!=NULL){
		return TLS_Recv_Data(ssl,buff,*len,timer,reason);
	}
	aslen=sizeof(struct sockaddr_in);
	FD_ZERO(&fdset);
	tv.tv_sec=timer;
	tv.tv_usec=0;
	*reason=0;

	memset((char *)&clientaddr_in,0,aslen);
	FD_SET(s,&fdset);
	n=select(s+1,&fdset,NULL,NULL,&tv);
	if(n<=0){
		*reason=RECV_TIME_OUT;
		return 0;
	}
	n=recvfrom(s,buff,*len,0,(struct sockaddr *)&clientaddr_in,&aslen);
	if(n<0){
		syserr("recfrom");
	}
	*cliaddr=(clientaddr_in.sin_addr.s_addr);
//	*cliaddr=ntohl(clientaddr_in.sin_addr.s_addr);
	*cliport=ntohs(clientaddr_in.sin_port);
	if(dump_flag==1){
		printf("Recv:\n");
		dump_packet(buff,n);
	}
	*len=n;
	return n;
}



size_t RecvDataMulti(int s1,int s2,unsigned char *buff,size_t *len,int *cliaddr,int *cliport,int timer,int *reason)
{
	size_t n;
	struct timeval tv;
	fd_set	fdset;
	struct sockaddr_in	clientaddr_in;
	socklen_t aslen;
	int	s;
	int	fdmax;

	aslen=sizeof(struct sockaddr_in);
	FD_ZERO(&fdset);
	tv.tv_sec=timer;
	tv.tv_usec=0;
	*reason=0;

	memset((char *)&clientaddr_in,0,aslen);
	fdmax=0;
	FD_SET(s1,&fdset);if(fdmax<s1) fdmax=s1;
	FD_SET(s2,&fdset);if(fdmax<s2) fdmax=s2;
	n=select(fdmax+1,&fdset,NULL,NULL,&tv);
	if(n<=0){
		*reason=RECV_TIME_OUT;
		return 0;
	}
	if(FD_ISSET(s1,&fdset)==1){
		s=s1;
	}else {
		s=s2;
	}
	n=recvfrom(s,buff,*len,0,(struct sockaddr *)&clientaddr_in,&aslen);
	if(n<0){
		syserr("recfrom");
	}
	if(cliaddr!=NULL){
		*cliaddr=(clientaddr_in.sin_addr.s_addr);
		//*cliaddr=ntohl(clientaddr_in.sin_addr.s_addr);
	}
	if(cliport!=NULL){
		*cliport=ntohs(clientaddr_in.sin_port);
	}
	if(dump_flag==1){
		printf("Recv:\n");
		dump_packet(buff,n);
	}
	*len=n;
	return s;
}


size_t SendData(char *host,int port,unsigned char *sbuff, size_t slen)
{
	int s;
	struct sockaddr_in	peeraddr_in;
	int	sendtolen,len;
	struct	hostent *hent;
	if(ssl!=NULL){
		return SSL_write(ssl,sbuff,slen);
	}

	len=sizeof(struct sockaddr_in);
	memset((char *)&peeraddr_in,0,len);
	/* Convert Host to IP ******************************/
	/*Peer IP */
	peeraddr_in.sin_addr.s_addr=inet_addr(host);
	if(peeraddr_in.sin_addr.s_addr==0||
			peeraddr_in.sin_addr.s_addr==0xFFFFFFFF){
		hent=gethostbyname(host);
		if(hent==NULL){
			return -1;
		}
		peeraddr_in.sin_addr.s_addr=
			*(unsigned int *)hent->h_addr_list[0];
	}
	/*Port設定*******************************************/	
	peeraddr_in.sin_family = AF_INET;
	peeraddr_in.sin_port = htons(port);
	/**********************************Socket生成*/
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if ( s <0 ) {
		return -1;
	}
	if(dump_flag == 1){
		unsigned char *ptr;
		ptr = (unsigned char *)&peeraddr_in.sin_addr.s_addr;
		printf("packet sent to -> %d.",*ptr++);
		printf("%d.",*ptr++);
		printf("%d.",*ptr++);
		printf("%d\n-------------------\n",*ptr++);
	}
	/*送信*****************************************************/
	if(dump_flag==1) dump_packet(sbuff,slen);
	for(sendtolen = slen ; sendtolen>0 ; sendtolen =- len){
		len=sendto(s,sbuff + slen - sendtolen  ,sendtolen ,0,
			(struct sockaddr *)&peeraddr_in,
			sizeof(peeraddr_in));
		if(len<0){
			/*send Error*********************/
			close(s);
			return -1;
		}
	}
	close(s);
	return 0;
}


size_t SendDataSocket(int s,char *host,int port,unsigned char *sbuff, size_t slen)
{
	struct sockaddr_in	peeraddr_in;
	int	sendtolen,len;
	struct	hostent *hent;

	len=sizeof(struct sockaddr_in);
	memset((char *)&peeraddr_in,0,len);
	/* Convert Host to IP ******************************/
	/*Peer IP */
	peeraddr_in.sin_addr.s_addr=inet_addr(host);
	if(peeraddr_in.sin_addr.s_addr==0||
			peeraddr_in.sin_addr.s_addr==0xFFFFFFFF){
		hent=gethostbyname(host);
		if(hent==NULL){
			return -1;
		}
		peeraddr_in.sin_addr.s_addr=
			*(unsigned int *)hent->h_addr_list[0];
	}
	/*Port設定*******************************************/	
	peeraddr_in.sin_family = AF_INET;
	peeraddr_in.sin_port = htons(port);
	/**********************************Socket生成*/
	if ( s <0 ) {
		return -1;
	}
	if(dump_flag == 1){
		unsigned char *ptr;
		ptr = (unsigned char *)&peeraddr_in.sin_addr.s_addr;
		printf("packet sent to -> %d.",*ptr++);
		printf("%d.",*ptr++);
		printf("%d.",*ptr++);
		printf("%d\n-------------------\n",*ptr++);
	}
	/*送信*****************************************************/
	if(dump_flag==1) dump_packet(sbuff,slen);
	for(sendtolen = slen ; sendtolen>0 ; sendtolen =- len){
		len=sendto(s,sbuff + slen - sendtolen  ,sendtolen ,0,
			(struct sockaddr *)&peeraddr_in,
			sizeof(peeraddr_in));
		if(len<0){
			/*send Error*********************/
			return -1;
		}
	}
	return 0;
}




void ConvertIP4(int addr,char *buff)
{
	int	i;
	unsigned char	*ptr;
	char	tmp[16];

	ptr=(unsigned char *)&addr;
	*buff='\0';

	for(i=0;i<4;i++){
		sprintf(tmp,"%d",ptr[i]);
		strcat(buff,tmp);
		if(i!=3){
			strcat(buff,".");
		}
	}
}
void InvertIP4(char *buff,int *addr)
{
	int	i,n;
	unsigned char	*ptr;
	unsigned int	tmp[4];
	ptr=(unsigned char *)addr;
	n=sscanf(buff,"%d.%d.%d.%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);
	if(n==4){
		for(i=0;i<4;i++){
			*ptr++=(unsigned char)tmp[i];
		}
	}
}
			
	
#ifdef TEST

main(int argc,char **argv)
{
	int n;

	if(argc<2){
		exit(1);
	}else{
		n=SendData("10.233.24.60",5060,argv[1],strlen(argv[1]));
	}
}
#endif


/************************/

