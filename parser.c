/***********************************************************************\

	SIP Server	

	Date		Ver		Author		MemoRandom
	Jul 3,2002	1.0		Hiroaki Hata	Created

	(C) 2002 All Copyrights reserved. 
*************************************************************************/
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include "udp.h"
#include "sip.h"
#include "parser.h"

extern int	dump_flag;





typedef struct {
	char	token[64];
	int	type;
	int	format;
}HTYPE;

static HTYPE mtype[]=
{
	{"INVITE",M_INVITE,0},
	{"ACK",M_ACK,0},
	{"OPTIONS",M_OPTIONS,0},
	{"BYE",M_BYE,0},
	{"CANCEL",M_CANCEL,0},
	{"REGISTER",M_REGISTER,0},
	{"SUBSCRIBE",M_SUBSCRIBE,0},
	{"MESSAGE",M_MESSAGE,0},
	{"INFO",M_INFO,0},
	{"",ELSE_H,0}
};

static HTYPE htype[]=
{
	{"Via",VIA_H,0},
	{"Expires",EXPIRES_H,0},
	{"Call-ID",CALLID_H,0},
	{"Content-Type",CONTENTTYPE_H,0},
	{"Content-Length",CONTENTLEN_H,0},
	{"User-Agent",USERAGENT_H,0},
	{"To",TO_H,0},
	{"T",TO_H,0},
	{"From",FROM_H,0},
	{"Cseq",CSEQ_H,0},
	{"CSeq",CSEQ_H,0},
	{"Contact",CONTACT_H,0},
	{"Max-Forwards",MAXFORWARDS_H,0},
	{"Record-Route",RECORDROUTE_H,0},
	{"Route",ROUTE_H,0},
	{"Proxy-Authenticate",PROXY_AUTHTC_H,0},
	{"Proxy-Authorization",PROXY_AUTHRZ_H,0},
	{"WWW-Authenticate",WWW_AUTHTC_H,0},
	{"",ELSE_H,0}
};




static char *get_line(char *buff,char *line);
static int analyze_header_type(char *buff,HTYPE *ptr);
static int analyze_header(char *buff,MESSAGE *mes);
static int first_line(char *buff,MESSAGE *mes);


/***************************************************************/
static char *get_line(char *buff,char *line)
// buffで示された位置から1行きりだしてlineに格納する
//進めたポインタ位置を返す
{
#define D	0x0d
#define	A	0x0a

	char	*ptr;
	char	*eol;
	int	n=0;

	*line='\0';
	if(*buff=='\0') return NULL;//EOT
	for(ptr=buff;;ptr++){
		if(n>(CLEN-10)){
			logging(2,"String too long (AnalyzeHeader 349)");
			logging(2,buff);
			return NULL;
		}
		switch(*ptr){
		case D:
			eol=ptr++;
			if(*ptr==A){
				ptr++;
			}
			*eol='\0';
			strcpy(line,buff);
			return ptr;
		case A:
			eol=ptr++;
			*eol='\0';
			strcpy(line,buff);
			return ptr;
		case '\0':
			strcpy(line,buff);
			return NULL;
		default:
			n++;
			break;
		}
	}
	return NULL;
}


static void LowerCase(char *p)
{
	for(;*p;p++){
		if(*p>='A' && *p<='Z') *p=*p+'a'-'A';
	}
}



static int analyze_header_type(char *buff,HTYPE *ptr)
{
	int i;
	char	tmp1[CLEN];
	char	tmp2[CLEN];

	if(*buff=='\0'||*buff==0x0a||*buff==0x0d) return Blank;
	strncpy(tmp1,buff,CLEN);
	LowerCase(tmp1);	
	for(i=0;ptr[i].token[0];i++){
		strncpy(tmp2,ptr[i].token,CLEN);
		LowerCase(tmp2);
		if(strcmp(tmp1,tmp2)==0){
			return ptr[i].type;
		}
	}
	return ELSE_H;
}



static int first_line(char *buff,MESSAGE *mes)
{
	int 	i,ret=OK;
	char	tmp[3][1024];
	char	*ptr[3];

	for(i=0;i<3;i++){
		ptr[i]=tmp[i];
	}
	if(strncmp(buff,"SIP",3)==0){
		//Response
		mes->start.type=RESPONSE;
		if(strlen(buff)>SCLEN-1){
			logging(2,"Firstline Size too long(Respose)");
			logging(2,buff);
			return NG;
		}
		strcpy(mes->start.response,buff);
		SeparateLex(buff,' ',ptr,3);
		mes->start.code=atoi(tmp[1]);
		ret=OK;
	}else{
		mes->start.type=REQUEST;
		SeparateLex(buff,' ',ptr,3);
		if(strlen(tmp[0]) >SCLEN-1) {
			logging(2,"Firstline Size too long");
			logging(2,tmp[0]);
			return NG;
		}
		strncpy(mes->start.method,tmp[0],SCLEN-1);
		if(strlen(tmp[1]) >SCLEN-1 ){
			logging(2,"Firstline Size too long");
			logging(2,tmp[1]);
			return NG;
		}


		/*
		 *
		strncpy(mes->start.sipuri,tmp[1],SCLEN-1);
		if(strlen(tmp[2]) >SCLEN-1) {
			logging(2,"Firstline Size too long");
			logging(2,tmp[2]);
			return NG;
		}
		*/

		AnalyzeURI(tmp[1],&mes->start.requri);


		strncpy(mes->start.proto,tmp[2],SCLEN-1);
		mes->start.message=analyze_header_type(tmp[0],mtype);
		if(mes->start.message==ELSE_H){
			ret=NG;
		}
	}
	return ret;

}


static int analyze_header(char *buff,MESSAGE *mes)
{
	int type;
	char	*p;
	VIA	*via;
	VIA	*v;
	URI	*uri;
	URI	*c;
	int	ret;
	GENERAL *g;
	GENERAL	*ptr;
	char	header[CLEN];
	PAUTH	*pauth;


	//Check Params
	if( buff==NULL||mes==NULL) {
		logging(3,"Param Error (Analyze Header:110)");
		return NG;
	}
	if(*buff=='\0'||*buff==0x0a||*buff==0x0d) return Blank;
	if(strlen(buff)>CLEN-1){
		logging(3,"Parameter too long(Analyze Header:115)");
		return NG;
	}
	//ヘッダ名を抽出
	strcpy(header,buff);
	p=strchr(header,':');
	if(p==NULL){
		logging(3,"No header Name (118)");
		return NG;
	}
	*p='\0';
	type=analyze_header_type(header,htype);
	if(type == ELSE_H){
		//非必須ヘッダ
		//-------------------------------------------
		g=(GENERAL *)malloc(sizeof(GENERAL));
		if(g==NULL){
			logging(3,"malloc error(Analyze Header:210)");
			return NG;
		}
		strncpy(g->body,buff,CLEN);
		g->next=NULL;
		if(mes->header.general==NULL){
			mes->header.general=g;
		}else{
			for(ptr=mes->header.general;ptr->next!=NULL;
					ptr=ptr->next){}
			ptr->next=g;
		}
	}else{ 
		//ヘッダ名を切り落とし
		p=strchr(buff,':');
		p++;
	}
DEBUG
	//printf("%d:%s\n",type,buff);
DEND
	switch(type){
	case VIA_H:
		via=(VIA *)malloc(sizeof(VIA));
		if(via ==NULL){
			logging(3,"malloc error(Analyze Header:212)");
			return NG;
		}
		memset(via,0,sizeof(VIA));
		ret=AnalyzeVia(p,via);
		if(ret!=OK){
			free(via);
			logging(2,"Via Analyze failed");
			logging(2,buff);
			return NG;
		}
		via->next=NULL;
		if(mes->header.via==NULL){
			mes->header.via=via;
		}else{
			for(v=mes->header.via;v->next!=NULL;v=v->next){}
			v->next=via;
		}
		break;
	case EXPIRES_H:
		ret=AnalyzeIntHeader(p,&mes->header.expires);
		if(ret!=OK){
			logging(2,"Expires Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case CALLID_H:
		ret=AnalyzeCharHeader(p,mes->header.callid);
		if(ret!=OK){
			logging(2,"Call-ID Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case USERAGENT_H:
		ret=AnalyzeCharHeader(p,mes->header.userAgent);
		if(ret!=OK){
			logging(2,"UserAgent Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case CONTENTTYPE_H:
		ret=AnalyzeCharHeader(p,mes->header.contentType);
		if(ret!=OK){
			logging(2,"Content-type Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case CONTENTLEN_H:
		ret=AnalyzeIntHeader(p,&mes->header.contentLength);
		if(ret!=OK){
			logging(2,"Content-len Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case MAXFORWARDS_H:
		ret=AnalyzeIntHeader(p,&mes->header.maxforwards);
		if(ret!=OK){
			logging(2,"Maxforwards Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case CSEQ_H:
		ret=AnalyzeCSeq(p,&mes->header.cseq);
		if(ret!=OK){
			logging(2,"CSEQ Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case TO_H:
		ret=AnalyzeURI(p,&mes->header.to);
		if(ret!=OK){
			logging(2,"To Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case FROM_H:
		ret=AnalyzeURI(p,&mes->header.from);
		if(ret!=OK){
			logging(2,"From Analyze failed");
			logging(2,buff);
			return NG;
		}
		break;
	case PROXY_AUTHRZ_H:
		if(mes->header.authrz != NULL){
			logging(2,"Duplicate Authorization Header");
			return NG;
		}
		pauth=(PAUTH *)malloc(sizeof(PAUTH));
		if(pauth==NULL){
			logging(2,"Memory short(Authorization)");
			return NG;
		}
		memset(pauth,0,sizeof(PAUTH));
		ret=AnalyzePAUTH(p,pauth);
		if(ret!=OK){
			free(pauth);
			logging(2,"Proxy-Authorization  Analyze failed");
			logging(2,buff);
			return NG;
		}
		mes->header.authrz=pauth;
		break;
	case PROXY_AUTHTC_H:
		if(mes->header.authtc != NULL){
			logging(2,"Duplicate Authenticate Header");
			return NG;
		}
		pauth=(PAUTH *)malloc(sizeof(PAUTH));
		if(pauth==NULL){
			logging(2,"Memory short(Authenticate)");
			return NG;
		}
		memset(pauth,0,sizeof(PAUTH));
		ret=AnalyzePAUTH(p,pauth);
		if(ret!=OK){
			free(pauth);
			logging(2,"Proxy-Authenticate  Analyze failed");
			logging(2,buff);
			return NG;
		}
		mes->header.authtc=pauth;
		break;
	case WWW_AUTHTC_H:
		if(mes->header.wwwauthtc != NULL){
			logging(2,"Duplicate Authenticate Header");
			return NG;
		}
		pauth=(PAUTH *)malloc(sizeof(PAUTH));
		if(pauth==NULL){
			logging(2,"Memory short(Authenticate)");
			return NG;
		}
		memset(pauth,0,sizeof(PAUTH));
		ret=AnalyzePAUTH(p,pauth);
		if(ret!=OK){
			free(pauth);
			logging(2,"Proxy-Authenticate  Analyze failed");
			logging(2,buff);
			return NG;
		}
		mes->header.wwwauthtc=pauth;
		break;
	case CONTACT_H:
		uri=(URI *)malloc(sizeof(URI));
		if(uri ==NULL){
			logging(2,"malloc error(Anlyze Header:215)");
			return NG;
		}
		memset(uri,0,sizeof(URI));
		ret=AnalyzeURI(p,uri);
		if(ret!=OK){
			free(uri);
			logging(2,"Contact Analyze failed");
			logging(2,buff);
			return NG;
		}
		uri->next=NULL;
		if(mes->header.contact==NULL){
			mes->header.contact=uri;
		}else{
			for(c=mes->header.contact;c->next!=NULL;c=c->next){}
			c->next=uri;
		}
		break;
	case RECORDROUTE_H:
		uri=(URI *)malloc(sizeof(URI));
		if(uri ==NULL){
			logging(2,"malloc error(Anlyze Header:345:R-R)");
			return NG;
		}
		memset(uri,0,sizeof(URI));
		ret=AnalyzeURI(p,uri);
		if(ret!=OK){
			free(uri);
			logging(2,"RouteRecord Analyze failed");
			logging(2,buff);
			return NG;
		}
		uri->next=NULL;
		if(mes->header.recordroute==NULL){
			mes->header.recordroute=uri;
		}else{
			for(c=mes->header.recordroute;c->next!=NULL;c=c->next){}
			c->next=uri;
		}
		break;
	case ROUTE_H:
		uri=(URI *)malloc(sizeof(URI));
		if(uri ==NULL){
			logging(2,"malloc error(Anlyze Header:348:R)");
			return NG;
		}
		memset(uri,0,sizeof(URI));
		ret=AnalyzeURI(p,uri);
		if(ret!=OK){
			free(uri);
			logging(2,"Route Analyze failed");
			logging(2,buff);
			return NG;
		}
		uri->next=NULL;
		if(mes->header.route==NULL){
			mes->header.route=uri;
		}else{
			for(c=mes->header.route;c->next!=NULL;c=c->next){}
			c->next=uri;
		}
		break;
	default:
		break;
	}
	return type;
}



int AnalyzePDU(char *rbuff,int rlen,MESSAGE *mes)
{

	char	line[CLEN];
	char	tmp[BLEN];
	char	*ptr;
	char	*ptr1;
	int	i,l=1;
	time_t	tick;
	int	type;
	int	checksheet[VIA_H+1];



	for(type=0;type<=VIA_H;type++){
		checksheet[type]=0;
	}
	ptr=rbuff;
	ptr=get_line(ptr,line);
	if(ptr==NULL) {
		logging(3,"Parameter Error(AnalyzePDU)");
		return NG-1;
	}
DEBUG
	printf("**************************************************************\n");
	time(&tick);
	sprintf(tmp,"(%s)R:%s:%s",mes->ip,line,ctime(&tick));
	logging(9,tmp);
DEND
	type=first_line(line,mes);
	if(type==NG){
		logging(2,"Packet Format Error(First Line)");
		logging(2,line);
		return NG-10;
	}

	for(;ptr!=NULL;){
		*line='\0';
		//getLine
		//行先頭が空白文字は、前の行の続き
		for(*tmp='\0';;){
			ptr1=get_line(ptr,tmp);
			l++;
			if(ptr1==NULL){
				type=NG;
				logging(3,"Line ends without CRLF");
				logging(3,tmp);
				goto label1;
			}
			ptr=ptr1;
			strcat(line,tmp);
			if(*ptr==' '||*ptr=='\t') continue;
			else break;

		}
		//HeaderType
		type=analyze_header(line,mes);
		if(type==Blank||type==NG){
			break;
		}else if(type<=VIA_H){
			checksheet[type]=1;
		}
	}
label1:
	if(type==NG){
		return NG-30;
	}else{
		//retreave contents;
		if(mes->header.contentLength>0){
DEBUG
//			printf("%s\n",ptr);
DEND
			mes->contents=(void *)malloc(mes->header.contentLength);
			if(mes->contents==NULL){
				logging(3,"Malloc Error(AnalyzePDU)");
				return NG-40;
			}else{
				memcpy(mes->contents,ptr,
					mes->header.contentLength);
			}
		}
	}
	l=0;
	//Check Mandatory Header in REQUEST
	if(mes->start.type==REQUEST){
		for(type=1;type<=VIA_H;type++){
			if(checksheet[type]==0){
				l=1;
				logging(2,"Header short");
				for(i=0;htype[i].token[0]!='\0';i++){
					if(htype[i].type==type){
						sprintf(line,"-Not Found (%s)",
							htype[i].token);
						logging(2,line);
					}
				}
			}
		}
	}
	if(l==1){return NG-50;}
	//レスポンスの場合、CSEQからメソッドを拾う
	if(mes->start.type==RESPONSE){
		for(type=0;mtype[type].type!=ELSE_H;type++){
			if(strcmp(mtype[type].token,mes->header.cseq.method)==0){
				mes->start.message=mtype[type].type;
				break;
			}
		}
	}


	if(mes->start.message==0){return NG-60;}
	else return OK;
}



#ifdef TEST

main()
{
	
	MESSAGE	mes;
	static void dump_packet(unsigned char *ptr,int len);
	char	rbuff[128];

	memset(&mes,0,sizeof(MESSAGE));
	sprintf(rbuff,"SIP/2.0 %d %s\r\nVia:SIP\r\n\r\n",200,"OK");
		
	dump_packet(rbuff,strlen(rbuff));
//	AnalyzePDU(rbuff,strlen(rbuff),&mes);

}
#endif



/************************/


