/***********************************************************************\

	SIP Client	

	Date			Ver		Author		MemoRandom
	2021/9/1	0.2a	Hata		

	(C) 2021 All Copyrights reserved. 
*************************************************************************/
#include <sys/types.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <error.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "udp.h"
#include "sip.h"
#include "parser.h"
#include "session.h"
#include "tls.h"

#define	CONF	"sip.conf"

extern int	dump_flag;
int debug=1;

static 	char	proxy_server[CLEN];
static	char	domain[CLEN];
static	char	HOSTID[CLEN];
static	int	HOSTPORT;
static	int	RTPPORT;
static  int TLS=0;
static void 	init_application(char *);
static	char	username[CLEN];
static	char	password[CLEN];
static	char	loginid[CLEN];
static	char	cacert[CLEN];
static	int	proxy_server_port;

#define	VER	"0.20 alpha"
#define	DATE	20211001

#ifdef EMULATION
int emulation=1;
static int RecvData_emu(int sock,char *rbuff,int *rlen,int *caddr,
		int *cport,int timeout,int *ret);
static void display_message(MESSAGE *mes);
#else
int emulation=0;
#endif
void Get_Ver(char *ver)
{
	sprintf(ver,"Free VC ver.%s(%d)",VER,DATE);
}

void	Get_SelfData(char *self_ip,int *self_port,char *self_username,char *self_domain,int *rtpport)
{
	if(self_ip!=NULL){
		strcpy(self_ip,HOSTID);
	}
	if(self_port!=NULL){
		*self_port=HOSTPORT;
	}
	if(self_username!=NULL){
		strcpy(self_username,username);
	}
	if(self_domain!=NULL){
		strcpy(self_domain,domain);
	}
	if(rtpport!=NULL){
		*rtpport=RTPPORT;
	}
}

void Get_ProxyData(char *plogin,char *ppasswd,char *pproxy,int *pport)
{
	if(plogin!=NULL){
		strcpy(plogin,loginid);
	}
	if(ppasswd!=NULL){
		strcpy(ppasswd,password);
	}
	if(pproxy!=NULL){
		strcpy(pproxy,proxy_server);
	}
	if(pport!=NULL){
		*pport=proxy_server_port;
	}
}
	


void syserr(char *mes)
{
	char	bf[128];
	if(errno == EINTR) return;
	if(strlen(mes)>80) mes[80]='\0';
	sprintf(bf,"ERROR: %s %d",mes,errno);
	logging(3,bf);
	logging(3,"     ;None System Error Message");
	exit(1);
}



static void init_application(char *filename)
{

	FILE	*fp;
	char	tag[80];
	char	value[80];
	char	buff[80];

	HOSTPORT=proxy_server_port=SIP_PORT;

	proxy_server[0]='\0';
	fp=fopen(filename,"r");
	if(fp==NULL){
		logging(3,"conf file error");
		exit(1);
	}
	for(;;){
		if(NULL==fgets(buff,80,fp)){
			break;
		}
		if(*buff=='#'||*buff=='\0'||*buff=='\n'){
			continue;
		}
		sscanf(buff,"%s %s",tag,value);
		if(strcmp("DOMAIN",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(DOMAIN)");
				exit(1);
			}
			strcpy(domain,value);
		}else if(strcmp("USER",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(USER)");
				exit(1);
			}
			strcpy(username,value);
		}else if(strcmp("PASSWORD",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(PASSWORD)");
				exit(1);
			}
			strcpy(password,value);
		}else if(strcmp("LOGINID",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(LOGINID)");
				exit(1);
			}
			strcpy(loginid,value);
		}else if(strcmp("PROXY",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(PROXY)");
				exit(1);
			}
			strcpy(proxy_server,value);
		}else if(strcmp("HOSTID",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(HOSTID)");
				exit(1);
			}
			strcpy(HOSTID,value);
		}else if(strcmp("RTPPORT",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(RTPPORT)\n");
				exit(1);
			}
			RTPPORT=atoi(value);
		}else if(strcmp("HOSTPORT",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(HOSTPORT)\n");
				exit(1);
			}
			HOSTPORT=atoi(value);
		}else if(strcmp("TLS",tag)==0){
			TLS=1;
		}else if(strcmp("PROXYPORT",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(PROXYPORT)\n");
				exit(1);
			}
			proxy_server_port=atoi(value);
		}else if(strcmp("CACERT",tag)==0){
			if(strlen(value)<=0 || strlen(value) >80){
				logging(3,"Conf:String length too long(CACERT)\n");
				exit(1);
			}
			strcpy(cacert,value);
		}
	}
	fclose(fp);
}

static int ProcessRequest(MESSAGE *mes)
{
	int ret=OK;
	int	peerport;
	char	peerip[32];
	int	addr;

	switch(mes->start.message){
	case M_ACK:
		ret=0;
		break;
	case M_BYE:
	case M_CANCEL:
		ret=DeleteSession(mes);
		ret=200;
		break;
	case M_INVITE:
		ret=ProcessINVITE(mes,peerip,&peerport);
		if(ret!=OK){
			DeleteSession(mes);
			ret=-400;
		}else{
			InvertIP4(peerip,&addr);
			printf("RTP:%s(%d) PORT:%d\n",peerip,addr,peerport);
			ret=RegisterSession(mes,0,INCOMMING,addr,peerport);
			if(ret!=OK){
				SendBYE(mes);
			}
			ret=-200;
		}
		break;
	case M_REGISTER:
	case M_SUBSCRIBE:
	case M_MESSAGE:
	default:
		ret=501;
		break;
	}
	return ret;
}


static int ProcessResponse(MESSAGE *mes)
{
//
//レスポンスを受信した場合、VIAヘッダを検索して転送先を決定する。
//VIAチェーンの最後尾に自サーバのアドレスが格納されていれば、
//自サーバ宛とみなし転送をかけない。VIAチェーンの最後尾が自分でなければ
//転送する。転送先は、VIAチェーンの先頭である.
//
//
//
	
	int ret=0;
	if(mes->start.message==M_REGISTER){
		RegisterResponse(mes);
	}else{
		logging(2,"Response Not found");
	}
	return ret ;
}



static void LoopProcess()
{
	char	rbuff[MAX_BUFF];
	char	*copybuff;
	char	ip[32];
	size_t	rlen;
	int	i;
	size_t	n;
	int	caddr;
	int	cport;
	int	ret;
	int	s;
	MESSAGE	*mes;
	pthread_t	pt;
	pthread_t	pt2;
	if( TLS	== 0){
		s=InitializeUDP(HOSTPORT);
	}else{
		s=InitializeTLS(cacert,proxy_server,proxy_server_port);
		s=SIP_E_OK;
		if(s!=SIP_E_OK){
			printf("ret=%d\n",s);
			logging(3,"Initialize TLS failed");
			return;
		}
		logging(1,"TLS connection opened");
		printf("TLS OK\n");
	}
	logging(1,"sipd starts----------------------");
	SendRegister(ON,NULL,TLS);
	/*
	ret=pthread_create(&pt,NULL,execute_receive_RTP,NULL);
	if(ret!=0){
		printf("Error Create Thread\n");
		exit(0);
	}
	ret=pthread_create(&pt2,NULL,execute_send_RTP,NULL);
	if(ret!=0){
		printf("Error Create Thread\n");
		exit(0);
	}
	*/
	for(i=0;;i++){
		//----------------------------------------Recv DataGram
		rlen=MAX_BUFF;
#ifdef EMULATION
		n=RecvData_emu(s,rbuff,&rlen,&caddr,&cport,5,&ret);
#else
		n=RecvData(s,(unsigned char*)rbuff,&rlen,&caddr,&cport,5,&ret);
#endif
		if(n==0){
			if(ret==RECV_TIME_OUT){
				CheckRegister();
				continue;
			}else{
				TLS_ClientShutdown();
				fprintf(stderr,"RecvData:%zu(%d)",n,ret);
				_exit(0);
			}
		}else if(n<0){
				TLS_ClientShutdown();
				fprintf(stderr,"RecvData:%zu",n);
				_exit(0);
		}
		rbuff[n]='\0';
		printf("%s\n",rbuff);
DEBUG
		printf("%s\n",rbuff);
DEND
		mes=(MESSAGE*)malloc(sizeof(MESSAGE));
		if(mes==NULL){break;}
		memset(mes,0,sizeof(MESSAGE));
		mes->header.expires=-1;
		mes->header.maxforwards=-1;
		rbuff[n]='\0';
		/*IPアドレスを取得*/
		if(TLS==0){
			ConvertIP4(caddr,ip);
			strcpy(mes->ip,ip);
			mes->port=cport;
		}
		copybuff=(char *)malloc(rlen);
		if(copybuff==NULL){
			logging(3,"recv buffer memory short ...101");
			continue;
		}
		mes->buff=copybuff;
		mes->len=rlen;
		memcpy(copybuff,rbuff,rlen);
		//Analyze DataGram
		ret=AnalyzePDU(rbuff,rlen,mes);
		if(ret==OK){
			/******************************/
DEBUG
			//	display_message(mes);
DEND
			/******************************/
			if(mes->start.type==REQUEST){
				ret=ProcessRequest(mes);
				if(ret>0){
					Response(ret,mes);
				}
			}else{
				ret=ProcessResponse(mes);
			}
		}else{
			logging(1,"AnalyzePDU Error");
		}
		if(ret!=-200){	
			free_message_buffer(mes);
			mes=NULL;
		}
DEBUG
		fflush(stdout);
DEND
		if(emulation==1) {
			sleep(2);
		}
	}
}


void display_message(MESSAGE *mes)
{
	VIA	*v;
	URI	*s;
	char	bf[BLEN];
	int	level=9;

	if(emulation==1) level=0;

	sprintf(bf,"----------------------------------");logging(level,bf);
	sprintf(bf,"position:%p",mes);logging(level,bf);
	sprintf(bf,"START.type:%d",mes->start.type);logging(level,bf);
	sprintf(bf,"START.message:%d",mes->start.message);logging(level,bf);
	sprintf(bf,"START.method:%s",mes->start.method);logging(level,bf);
	sprintf(bf,"START.REQ-URI(host):%s\n",mes->start.requri.host);
	sprintf(bf,"START.proto:%s",mes->start.proto);logging(level,bf);
	sprintf(bf,"START.code:%d",mes->start.code);logging(level,bf);
	//------------
	logging(level,"From-----------------------------");
	DisplayURI(level,&mes->header.from);
	logging(level,"To-----------------------------");
	DisplayURI(level,&mes->header.to);
	for(s=mes->header.contact;s!=NULL;s=s->next){
		logging(level,"Contact-----------------------------");
		DisplayURI(level,s);
	}
	for(s=mes->header.route;s!=NULL;s=s->next){
		logging(level,"Route-----------------------------");
		DisplayURI(level,s);
	}
	for(s=mes->header.recordroute;s!=NULL;s=s->next){
		logging(level,"Route-Record-----------------------------");
		DisplayURI(level,s);
	}
	for(v=mes->header.via;v!=NULL;v=v->next){;
		sprintf(bf,"Via=%p",v);logging(level,bf);
		sprintf(bf,"Via.proto:%s",v->proto);logging(level,bf);
		sprintf(bf,"Via.ver:%s",v->ver);logging(level,bf);
		sprintf(bf,"Via.trans:%s",v->trans);logging(level,bf);
		sprintf(bf,"Via.host:%s",v->host);logging(level,bf);
		sprintf(bf,"Via.port:%d",v->port);logging(level,bf);
		sprintf(bf,"Via.param.branch:%s",v->param.branch);
					logging(level,bf);
	}
	sprintf(bf,"CSeq.seq:%d",mes->header.cseq.seq);logging(level,bf);
	sprintf(bf,"CSeq.met:%s",mes->header.cseq.method);logging(level,bf);
	sprintf(bf,"Call-id:%s",mes->header.callid);logging(level,bf);
	printf("Proxy-Authenticate-----------------\n");
	DisplayPAUTH(mes->header.authtc);
	printf("Proxy-Authorization-----------------\n");
	DisplayPAUTH(mes->header.authrz);
}

int main(int argc,char **argv)
{
	char	filename[128];
	time_t	t;

	time(&t);
	srand(t);
	strcpy(filename,CONF);
	init_application(filename);
	InitSession();
	LoopProcess();
	return 0;
}


/************************/
#ifdef EMULATION
static int RecvData_emu(int sock,char *rbuff,int *rlen, int *caddr,
		int *cport,int timeout,int *ret)
{
	char	buff[1024];
	static FILE	*fp=NULL;
	char	*ptr;

	debug=1;	
	if(rbuff==NULL) return -1;
	*rbuff='\0';
	if(fp==NULL){
		fp=fopen("testdata.txt","r");
		if(fp==NULL) return -1;
	}
	for(;fgets(buff,1000,fp);){
		//改行コードを削除
		if(*buff=='*') break;
		for(ptr=buff;*ptr!='\0';ptr++){
			if(*ptr=='\r'|| *ptr=='\n'){
				*ptr='\0';
			}

		}
		strcat(rbuff,buff);
		//インターネット改行コードを挿入
		strcat(rbuff,"\r\n");
	}
	fclose(fp);
	*rlen=strlen(rbuff);
	*caddr=htonl(10*256*256*256+168*256*256+1);
	*cport=SIP_PORT;
	*ret=0;
	if(*rlen ==0){
		fclose(fp);
		fp=NULL;
		printf("NO Data to Recv\n");
	}
//	dump_packet(rbuff,*rlen);
	return *rlen;
}

#endif

