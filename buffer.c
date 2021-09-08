#include <sys/types.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "sip.h"
#include "parser.h"
#define	ALL		0
#define	INSIDE	1
#define	OUTSIDE	2

static void params_to_asc(URIPARAM *param,char *buff,size_t blen,int type);
static int check_ip(char *p)
{
	for(;*p!='\0';p++){
		if(*p>='0' && *p<='9') continue;
		if(*p=='.') continue;
		return NG;
	}
	return OK;
}

int MakeURItoASC(URI *uri,char *buff,int type)
{
	//type 1 
	//type 2 
	char	line[6000];
	int	crlf=0;
	int	brace=0;
	int	displayname=0;
	char	header[BLEN];
	char	host[128];

	

	//type 1 括弧あり
	//type 2 改行あり
	crlf= type & CRLF;
	brace = type & BRACE;
	displayname = type & DISPLAYNAME;

	if(*uri->proto=='\0'){
                strcpy(uri->proto,"sip");
    }
    if(brace != 0){
            sprintf(header,"<%s:",uri->proto);
    }else{
            sprintf(header,"%s:",uri->proto);
    }
	if(buff==NULL) {
		logging(2,"param error MakeURItoASC");
		return NG;
	}
	*buff='\0';
    //Display Name if Any
	if( displayname!=0 && uri->display[0]!='\0'){
		sprintf(buff,"\"%s\" ",uri->display);
	}
	//IPv6
	if(strchr(uri->host,':')==NULL){
		strcpy(host,uri->host);
	}else{
		strcpy(host,"[");
		strcat(host,uri->host);
		strcat(host,"]");
	}
	if(uri->username[0]!='\0'){
		if(uri->port!=0){
			sprintf(line,"%s%s@%s:%d", 
				header,uri->username, host,uri->port);
		}else{
			sprintf(line,"%s%s@%s", 
				header,uri->username, host);
		}
	}else{
		if(uri->port!=0){
			sprintf(line,"%s%s:%d", 
				header, host,uri->port);
		}else{
			sprintf(line,"%s%s", 
				header,host);
		}
	}
	strcat(buff,line);
	*line=0;
	params_to_asc(&uri->param,line,sizeof(line),INSIDE);
	strcat(buff,line);
	if(brace!=0) strcat(buff,">");//Mar.11.2005パラメータは括弧外に出す
	params_to_asc(&uri->param,line,sizeof(line),OUTSIDE);
	strcat(buff,line);
	strcat(buff,uri->aux);
	if(crlf!=0) strcat(buff,"\r\n");
	return OK;
}

int MakeAnonymous(URI *uri,char *buff)
{
	//type 1 
	//type 2 
	char	line[6000];
	int	crlf=0;
	int	brace=0;
	char	header[BLEN];
	char	host[128];
	
	//type 1 括弧あり
	//type 2 改行あり
	crlf= 1;
	brace = 1;

	if(buff==NULL) {
		logging(2,"param error MakeURItoASC");
		return NG;
	}
	//IPv6
	if(strchr(uri->host,':')==NULL){
		strcpy(host,uri->host);
	}else{
		strcpy(host,"[");
		strcat(host,uri->host);
		strcat(host,"]");
	}
	sprintf(header,"<%s:",uri->proto);
	*buff='\0';
	sprintf(line,"%s%s@%s", header,"anonymous", host);
	strcat(buff,line);
	*line='\0';
	params_to_asc(&uri->param,line,sizeof(line),ALL);
	strcat(buff,line);
	if(brace!=0) strcat(buff,">");
	strcat(buff,uri->aux);
	if(crlf!=0) strcat(buff,"\r\n");
	return OK;
}

int MakeRemotePrtyID(URI *uri,char *buff)
{
	//type 1 
	//type 2 
	char	line[6000];
	int	crlf=0;
	int	brace=0;
	char	header[BLEN];
	char	host[128];
	
	crlf= 1;
	brace = 1;

	if(buff==NULL) {
		logging(2,"param error MakeURItoASC");
		return NG;
	}
	//IPv6
	if(strchr(uri->host,':')==NULL){
		strcpy(host,uri->host);
	}else{
		strcpy(host,"[");
		strcat(host,uri->host);
		strcat(host,"]");
	}
	sprintf(header,"<%s:",uri->proto);
	*buff='\0';
	sprintf(line,"%s%s@%s", header,uri->username, host);
	strcat(buff,line);
	*line='\0';
	params_to_asc(&uri->param,line,sizeof(line),ALL);
	strcat(buff,line);
	if(brace!=0) strcat(buff,">");
	strcat(buff,";privacy=full");
	if(crlf!=0) strcat(buff,"\r\n");
	return OK;
}



int MakeSendBuffer(MESSAGE *mes,char *buff)
{	
	char	line[BLEN];
	char	username[CLEN];
	VIA	*via;
	URI	*p;
	GENERAL	*g;
	char	*ptr;
	URI		to;
	//HTYPE	*mlist;

	if(buff==NULL) return -1;
	*buff='\0';
	

	//--------------------------------------------------First Line
	//Escaping Special Char 2005/09/22
	memcpy(&to,&mes->start.requri,sizeof(URI));
	strcpy(username,to.username);
	EncodeEscapeString(username,to.username);

	if(mes->start.type==REQUEST){
		if(mes->start.requri.username[0]=='\0'){
			if(strchr(mes->start.requri.host,':')==NULL){
				sprintf(line,"%s sip:%s",mes->start.method,	mes->start.requri.host);
			}else{//IPv6
				sprintf(line,"%s sip:[%s]",mes->start.method,mes->start.requri.host);
			}
			strcat(buff,line);
		}else{
			if(strchr(mes->start.requri.host,':')==NULL){
				sprintf(line,"%s sip:%s@%s",
					mes->start.method,
					to.username,
					to.host);
			}else{//IPv6
				sprintf(line,"%s sip:%s@[%s]",
					mes->start.method,
					to.username,
					to.host);

			}
			strcat(buff,line);
		}
		*line='\0';
		strcat(buff,line);
		strcat(buff," ");
		strcat(buff,mes->start.proto);
		strcat(buff,"\r\n");
	}else{
		sprintf(line,"%s\r\n",mes->start.response);
		strcat(buff,line);
	}
	//-------------------------------------------------Via Header
	via=mes->header.via;
	if(via==NULL){
		logging(1,"no via entry(334)\n");
		return NG;
	}
	for(;via!=NULL;via=via->next){
		if(strchr(via->host,':')==NULL){
			if(via->port==0){
				snprintf(line,sizeof(line),"Via: %s/%s/%s %s",
					via->proto,
					via->ver,
					via->trans,
					via->host);
			}else{
				snprintf(line,sizeof(line),"Via: %s/%s/%s %s:%d",
					via->proto,
					via->ver,
					via->trans,
					via->host,
					via->port);
			}
		}else{//IPv6
			snprintf(line,sizeof(line),"Via: %s/%s/%s [%s]:%d",
				via->proto,
				via->ver,
				via->trans,
				via->host,
				via->port);
		}
		strcat(buff,line);
		*line='\0';
		params_to_asc(&via->param,line,sizeof(line),ALL);
		strcat(buff,line);
		strcat(buff,"\r\n");
	}
	//----------------------------------------------------MaxForwards
	if(mes->header.maxforwards>0){
		sprintf(line,"Max-Forwards: %d\r\n",mes->header.maxforwards);
		strcat(buff,line);
	}
	//-------------------------------------------------------From
	strcat(buff,"From: ");
	MakeURItoASC(&mes->header.from,line,BRACE|CRLF|DISPLAYNAME);
	strcat(buff,line);
	//-------------------------------------------------------Remote-Party-ID
	/*
	if(priv==1){
		strcat(buff,"Remote-Party-ID: ");
		MakeRemotePrtyID(&mes->header.from,line);
		strcat(buff,line);
	}
	*/
	//-------------------------------------------------------proxy-require
	/*
	if(priv==1){
		strcpy(line,"proxy-require: privacy\r\n");
		strcat(buff,line);
	}
	*/
	//-------------------------------------------------------To
	strcat(buff,"To: ");
	//Escaping Special Char 2005/09/22
	memcpy(&to,&mes->header.to,sizeof(URI));
	strcpy(username,to.username);
	EncodeEscapeString(username,to.username);

	if(strncmp(to.username,"8150",4)==0){//2005/7/27
		MakeURItoASC(&to,line,BRACE|CRLF);
	}else{
		MakeURItoASC(&to,line,BRACE|CRLF|DISPLAYNAME);
	}
	strcat(buff,line);
	//-----------------------------------------------------CALL-ID
	sprintf(line,"Call-ID: %s\r\n",mes->header.callid);
	strcat(buff,line);
	//-----------------------------------------------------CSEQ
	if(*mes->header.cseq.method!='\0'){
		sprintf(line,"CSeq: %d %s\r\n",
			mes->header.cseq.seq,
			mes->header.cseq.method);
		strcat(buff,line);
	}
	//------------------------------------------------- Contact
	for( p=mes->header.contact;p!=NULL;p=p->next){
		if(p->host[0]=='\0'){
			strcat(buff,"Contact:*\r\n");
		}else{
			strcat(buff,"Contact: ");
			MakeURItoASC(p,line,BRACE|CRLF);
			strcat(buff,line);
		}
	}
	//--------------------------------------------------User Agent
	if(*mes->header.userAgent!='\0'){
		sprintf(line,"User-Agent: %s\r\n",mes->header.userAgent);
		strcat(buff,line);
	}
	//----------------------------------------------------Expires
	if(mes->header.expires>=0){
		sprintf(line,"Expires: %d\r\n",mes->header.expires);
		strcat(buff,line);
	}
	//-------------------------------------------------Record-Route 
	for( p=mes->header.recordroute;p!=NULL;p=p->next){
		strcat(buff,"Record-Route: ");
		MakeURItoASC(p,line,BRACE|CRLF);
		strcat(buff,line);
	}
	//-------------------------------------------------Route 
	for( p=mes->header.route;p!=NULL;p=p->next){
		if(NG==check_ip(p->host)) break;
		strcat(buff,"Route: ");
		MakeURItoASC(p,line,BRACE|CRLF);
		strcat(buff,line);

	}
	strcat(buff,"Allow: OPTIONS, INVITE, ACK, REFER, CANCEL, BYE, NOTIFY\r\n");

	strcat(buff,"Contact: <sip:fmc36956250@127.0.0.1;transport=tls>\r\n");
	strcat(buff,"Expires: 3600\r\n");


	//-------------------------------------------------Allow
	/*
	if(mes->header.allow!=0){
		mlist=GetMethodList();
		strcat(buff,"Allow: ");
		for(i=0;mlist[i].token[0]!='\0';i++){
			if((mes->header.allow & mlist[i].pos)==mlist[i].pos){
				strcat(buff,mlist[i].token);
				strcat(buff,",");
			}
		}
		buff[strlen(buff)-1]='\0';
		strcat(buff,"\r\n");
	}
	*/
	//-------------------------------------------------Proxy Authorization
	if(mes->header.authrz!=NULL){
		strcat(buff,"Proxy-Authorization: Digest ");
		sprintf(line,"username=\"%s\", ",mes->header.authrz->username);
		strcat(buff,line);
		sprintf(line,"realm=\"%s\", ",mes->header.authrz->realm);
		strcat(buff,line);
		sprintf(line,"domain=\"%s\", ",mes->header.authrz->domain);
		strcat(buff,line);
		if(*mes->header.authrz->algorithm!='\0'){
			sprintf(line,"algorithm=%s, ",mes->header.authrz->algorithm);
			strcat(buff,line);
		}
		sprintf(line,"uri=\"%s\", ",mes->header.authrz->uri);
		strcat(buff,line);


		sprintf(line,"nonce=\"%s\",",mes->header.authrz->nonce);
		strcat(buff,line);
		if(*mes->header.authrz->opaque!='\0'){
			sprintf(line,"opaque=\"%s\",",mes->header.authrz->opaque);
			strcat(buff,line);
		}

		if(*mes->header.authrz->qop!='\0'){
			sprintf(line,"qop=%s,",mes->header.authrz->qop);
			strcat(buff,line);
			sprintf(line,"nc=%s,",mes->header.authrz->nc);
			strcat(buff,line);
			sprintf(line,"cnonce=\"%s\",",mes->header.authrz->cnonce);
			strcat(buff,line);
		}

		sprintf(line,"response=\"%s\",",mes->header.authrz->response);
		strcat(buff,line);

		//末尾がカンマで終わったらカンマを削除
		if(buff[strlen(buff)-1]==',') buff[strlen(buff)-1]='\0';
		//末尾に改行を挿入
		strcat(buff,"\r\n");
	}
	//-------------------------------------------------Authorization
	if(mes->header.wwwauthrz!=NULL){
		strcat(buff,"Authorization: Digest ");
		sprintf(line,"username=\"%s\",",mes->header.wwwauthrz->username);
		strcat(buff,line);
		sprintf(line,"realm=\"%s\",",mes->header.wwwauthrz->realm);
		strcat(buff,line);
		sprintf(line,"domain=\"%s\", ",mes->header.wwwauthrz->domain);
		strcat(buff,line);
		sprintf(line,"nonce=\"%s\",",mes->header.wwwauthrz->nonce);
		strcat(buff,line);
		sprintf(line,"uri=\"%s\",",mes->header.wwwauthrz->uri);
		strcat(buff,line);

		if(*mes->header.wwwauthrz->opaque!='\0'){
			sprintf(line,"opaque=\"%s\",",mes->header.wwwauthrz->opaque);
			strcat(buff,line);
		}else{
			strcat(buff,"opaque=\"\",");
		}
		if(*mes->header.wwwauthrz->algorithm!='\0'){
			sprintf(line,"algorithm=%s,",mes->header.wwwauthrz->algorithm);
			strcat(buff,line);
		}
		if(*mes->header.wwwauthrz->stale!='\0'){
			//sprintf(line,"stale=%s,",mes->header.wwwauthrz->stale);
			//strcat(buff,line);
		}
		if(*mes->header.wwwauthrz->qop!='\0'){
			sprintf(line,"qop=%s,",mes->header.wwwauthrz->qop);
			strcat(buff,line);
			sprintf(line,"nc=%s,",mes->header.wwwauthrz->nc);
			strcat(buff,line);
			sprintf(line,"cnonce=\"%s\",",mes->header.wwwauthrz->cnonce);
			strcat(buff,line);
		}
		sprintf(line,"response=\"%s\"",mes->header.wwwauthrz->response);
		strcat(buff,line);	

		//末尾がカンマで終わったらカンマを削除
		if(buff[strlen(buff)-1]==',') buff[strlen(buff)-1]='\0';
		//末尾に改行を挿入
		strcat(buff,"\r\n");
	}

	//-------------------------------------------------General Header
	for(g=mes->header.general;g!=NULL;g=g->next){
		if(*g->body){
			if(strncmp(g->body,"Proxy-Auth",10)==0){
				continue;
			}
			//
			strcat(buff,g->body);
			strcat(buff,"\r\n");
		}
	}	
	//-------------------------------------------------Content-Type
	if(*mes->header.contentType!='\0'&& 
			mes->header.contentLength!=0){
		sprintf(line,"Content-Type: %s\r\n",mes->header.contentType);
		strcat(buff,line);
	}
	//-------------------------------------------------Content-Length
	sprintf(line,"Content-Length: %d\r\n",mes->header.contentLength);
	strcat(buff,line);

	//=================================================AUX Headers
	//AuxMakeSendBuffer(buff,mes);
	//-------------------------------------------------Contents
	strcat(buff,"\r\n");
	if(mes->contents!=NULL){
		ptr=&buff[strlen(buff)];
		memcpy(ptr,mes->contents,mes->header.contentLength);
		ptr=ptr+mes->header.contentLength;
		*ptr='\0';
	}
	return OK;	
}

static void params_to_asc(URIPARAM *param,char *buff,size_t blen,int type)
{
	char	line[BLEN];

	if(param==NULL||buff==NULL) {
		logging(2,"Invaid param params_to_asc)");
		return ;
	}
	*buff='\0';
	//Header Parameter
	if(type==ALL||type==OUTSIDE){
		if(param->q>0 && param->q<1){
			sprintf(line,";q=%1.3f",param->q);
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,line);
		}
		if(*param->branch){
			sprintf(line,";branch=%s",param->branch);
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,line);
		}
		if(param->rport==1){
			strcpy(line,";rport");
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,line);
		}
		if(*param->tag){
			sprintf(line,";tag=%s",param->tag);
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,line);
		}
	#ifndef _I_Teamese
		if(*param->aux){
			strcat(buff,param->aux);
		}
	#endif
	}
	//URI parameter
	if(type==ALL||type==INSIDE){
		if(*param->maddr){
			snprintf(line,sizeof(line),";maddr=%s",param->maddr);
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,line);
		}

		if(param->ttl){
			snprintf(line,sizeof(line),";ttl=%d",param->ttl);
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,line);
		}
		if(*param->transport!='\0'){
			snprintf(line,sizeof(line),";transport=%s",param->transport);
			printf("***********%ld\n",blen);
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,line);
		}
		if(*param->user){
			snprintf(line,sizeof(line),";user=%s",param->user);
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,line);
		}
		if(*param->method){
			snprintf(line,sizeof(line),";method=%s",param->method);
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,line);
		}
		if(param->lr==1){
			if(strlen(buff)+strlen(line)<blen)
				strcat(buff,";lr");
		}
	}

}

