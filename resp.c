#include <sys/types.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include "udp.h"
#include "sip.h"
#include "parser.h"

const struct {
	int	code;
	char	msg[64];
} ret_code[]={
	{E_TRYING,"Trying"},
	{E_RINGING,"Ringing"},
	{E_OK,"OK"},
	{E_BADREQ,"Bad Request"},
	{E_UNAUTH,"Unauthorized"},
	{E_NOTFOUND,"Fot Found"},
	{E_NOTALLOW,"Method Not Allowed"},
	{E_NOTACCEPT,"Not Acceptable"},
	{E_TIMEOUT,"Request Timeout"},
	{E_GONE,"Gone"},
	{E_MEDIATYPE,"Unsupported Media Type"},
	{E_URI,"Unsupported URI Scheme"},
	{E_TRANSACTION,"Call/Transaction Does Not Exist"},
	{E_MANYHOP,"Too Many Hops"},
	{E_BUSY,"Busy Here"},
	{E_REQTERM,"Request Terminated"},
	{E_SERVER,"Server Internal Error"},
	{E_IMPLEMENT,"Not Implemented"},
	{E_GATEWAY,"Bad Gateway"},
	{E_VERSION,"Version Not Supported"},
	{-1,""}};
extern int	dump_flag;
static int make_response_message(int resp, char *buff,MESSAGE *mes);
static int code_index(int code);





void Response(int code,MESSAGE *mes)
{
	char	sbuff[MAX_BUFF];
	char	ip[32];
	short	cport;
	VIA	*v;

	//MakeResponseBuffer
	if(make_response_message(code,sbuff,mes)<0){
		return ;
	}
DEBUG
	printf("%s\n",sbuff);
DEND
	/*
	for(v=mes->header.via;v->next!=NULL;v=v->next){}
	*/
	v=mes->header.via;
	if(v==NULL){
		logging(1,"no via entry(324)");
		return;
	}
	
	cport=v->port;
	if(cport==0) cport=SIP_PORT;
	strcpy(ip,v->host);
	sbuff[strlen(sbuff)]='\0';
	printf("Send %zu bytes\n",strlen(sbuff));
	printf("%s\n",sbuff);
	SendData(ip,cport,(unsigned char *)sbuff,strlen(sbuff));
}

static int code_index(int code)
{
	int i;
	for(i=0;ret_code[i].code>0;i++){
		if(ret_code[i].code==code){
			return i;
		}
	}
	return 0;
}



static int make_response_message(int resp, char *buff,MESSAGE *mes)
{	
	int	idx;
	int	ret;	
	
	if(buff==NULL||mes==NULL) return NG;
	*buff='\0';
	//First Line
	mes->start.type=RESPONSE;
	mes->start.code=resp;
	idx=code_index(resp);
	sprintf(mes->start.response,
		"SIP/2.0 %d %s",resp,ret_code[idx].msg);
	ret=MakeSendBuffer(mes,buff);
	return ret;
}

