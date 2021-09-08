#include <sys/types.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <wait.h>
#include <pthread.h>
#include "udp.h"
#include "sip.h"
#include	"session.h"
#define	PR	printf

int ProcessINVITE(MESSAGE *mes,char *ip,int *port)

{
	MESSAGE	*rep;
	URI	*contact;
	int	rport;
	char	*sdp;
	int	len;
	int	ret;
	char	peerip[32];
	int	peerport;
	char	hostid[256];
	char	username[256];
	int	init=0;
	char	logmes[BLEN];

	sprintf(logmes,"INVITE From:%s",mes->header.from.username);
	PR("%s\n",logmes);
	logging(2,logmes);
	Get_SelfData(hostid,NULL,username,NULL,&rport);
	return NG;
	//送信用データエリアの確保
	rep=(MESSAGE *)malloc(sizeof(MESSAGE));
	if(rep==NULL) {
		PR("Memory Short\n");
		return NG;
	}
	memset(rep,0,sizeof(URI));
	if(strstr(mes->header.to.aux,"tag")==NULL){
		sprintf(mes->header.to.aux,";tag=%d-%d",getpid(),rand());
		init=1;
	}
	// リプライ用データを作製
	copy_message_buffer(rep,mes);
	Response(500,rep);
	goto final;
	// Replay 100
	Response(100,rep);
	contact=(URI *)malloc(sizeof(URI));
	if(contact==NULL) {
		PR("Memory Short\n");
		Response(500,rep);
		goto final;
	}
	memset(contact,0,sizeof(URI));
	strcpy(contact->host,hostid);
	strcpy(contact->username,username);
	rep->header.contact=contact;
	//Analyze Sound Parameter

	peerport=0;
	*peerip='\0';
	ret=AnalyzeSDP( mes->contents,
			mes->header.contentLength,
			peerip,&peerport);
	if(ret==NG||peerport==0||*peerip=='\0') {
		PR("Recv SDP Analyze Error(%d)\n",ret);
		Response(500,rep);
		goto final;
	}
	if(init==1){		
		//Create Sound Sessions
		// Reply 180
		Response(180,rep);
		sleep(3);
	}
	sdp=NULL;
	//Make SD
	len=MakeSDP( mes->header.to.username, rport,&sdp);
	if(sdp==NULL){
		PR("Recv SDP Composing Error(%d)\n",ret);
		Response(500,rep);
		goto final;
	}else{
		strcpy(rep->header.contentType, "application/sdp");
		rep->header.contentLength=len;
		rep->contents=sdp;
	}
	//Reply 200
	Response(200,rep);
	sprintf(logmes,"Reply 200 Romote RTP IP :%s  Port:%d",peerip,peerport);
	logging(2,logmes);
	PR("%s\n",logmes);
final:
	if(sdp)free(sdp);
	rep->header.contentLength=0;
	rep->contents=NULL;
	free_message_buffer(rep);
	strcpy(ip,peerip);
	*port=peerport;
	return OK;
}


static int  MakeBYE(MESSAGE *mes,MESSAGE **pbye)
{
	MESSAGE *bye;
	URI	*ptr;
	URI	*route;
	URI	**next;
	VIA	*via;
	char	hostid[256];
	int	hostport;

	
	//メモリー領域を確保
	bye=(MESSAGE *)malloc(sizeof(MESSAGE));
	if(bye==NULL) return NG-100;
	memset(bye,0,sizeof(MESSAGE));
	//ファーストライン
	bye->start.type=REQUEST;
	bye->start.message=M_BYE;
	strcpy(bye->start.method,"BYE");
	if((ptr=mes->header.contact)!=NULL){
		memcpy(&bye->start.requri,ptr,sizeof(URI));
	}else{
		memcpy(&bye->start.requri,&mes->header.from,sizeof(URI));
	}
	strcpy(bye->start.proto,"SIP/2.0");
	bye->start.ver=2;
	//CallID
	strcpy(bye->header.callid,mes->header.callid);
	//From
	memcpy(&bye->header.from, &mes->header.to,sizeof(URI));
	//To
	memcpy(&bye->header.to, &mes->header.from,sizeof(URI));
	//CSeq
	bye->header.cseq.seq=1;
	strcpy(bye->header.cseq.method,"BYE");
	//Via
	printf("Make Bye Landmark35\n");fflush(stdout);
	via=(VIA *)malloc(sizeof(VIA));
	if(via==NULL){
		free_message_buffer(bye);
		return NG-200;
	}
	Get_SelfData(hostid,&hostport,NULL,NULL,NULL);
	memset(via,0,sizeof(VIA));
	strcpy(via->proto,"SIP");
	strcpy(via->ver,"2.0");
	strcpy(via->trans,"UDP");
	strcpy(via->host,hostid);
	via->port=hostport;
	sprintf(via->param.branch,"%s%d",MAGIC,getpid());
	bye->header.via=via;
	//Content-Length
	bye->header.contentLength=0;
	//MaxFofwards
	bye->header.maxforwards=70;
	//Route , Record-Routeから構成する
	next=&bye->header.route;
	printf("Make Bye Landmark4sfdds654\n");fflush(stdout);
	for(ptr=mes->header.recordroute;ptr!=NULL;ptr=ptr->next){
		printf("RR:%s\n",ptr->host);
		route=(URI *)malloc(sizeof(URI));
		memset(route,0,sizeof(URI));
		if(route==NULL){
			free_message_buffer(bye);
			return NG-200;
		}
		memcpy(route,ptr,sizeof(URI));
		route->next=NULL;
		*next=route;
		next=&route->next;
	}
	printf("Make Bye Landmark44\n");fflush(stdout);
	//Routeレコードの最終行はINVITEのContact:
	route=(URI *)malloc(sizeof(URI));
	if(route==NULL){
		free_message_buffer(bye);
		return NG-200;
	}
	memcpy(route,mes->header.contact,sizeof(URI));
	route->next=NULL;
	*next=route;
	*pbye=bye;	
	printf("Make Bye Landmark99\n");fflush(stdout);
	return OK;
	
}
	

int SendBYE(MESSAGE *mes)
{
	int	ret;
	char	sbuff[4000];
	MESSAGE *bye;
	URI	*ptr;

	PR("SendBYE\n");
	fflush(stdout);
	memset(sbuff,0,4000);
	ret=MakeBYE(mes,&bye);
	if(ret!=OK){
		printf("Make Bye Error = %d\n",ret);
		return ret;
	}
	ret=MakeSendBuffer(bye,sbuff);
	free_message_buffer(bye);
	if(ret!=OK){
		return NG;
	}
	if(mes->header.recordroute!=NULL){
		ptr=mes->header.recordroute;
	}else{
		ptr=mes->header.contact;
	}
	if(ptr==NULL){
		PR("Send Unable\n");
		return  NG;
	}
	if(ptr->port==0) ptr->port=5060;
	PR("Sending BYE to %s(%d)\n",ptr->host,ptr->port);
	fflush(stdout);
	SendData(ptr->host,ptr->port,(unsigned char*)sbuff,strlen(sbuff));
	return OK;
}

