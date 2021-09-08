#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "sip.h"
#define	BMAX	1000
#define	SP_SP	1
#define	SP_EQ	2
#define	SP_LF	3

int MakeSDP(char *username,int port,char **p)
{

	char	buff[1024];
	char	tmp[1024];
	int	len;
	int	total;
	char	*sdp;
	char	hostid[256];
	time_t	t;


	time(&t);

	
	Get_SelfData(hostid,NULL,NULL,NULL,NULL);
	buff[0]=0;
	//Protocol Version
	total=strlen(buff);
	sprintf(tmp,"v=%d\r\n",0);
	len=strlen(tmp);
	if(total+len >BMAX) return NG;
	strcat(buff,tmp);
	//Creater
	total=strlen(buff);
	sprintf(tmp,"o=%09ld %d %d IN IP4 %s\r\ns=session\r\n",
			t,0,1,hostid);
	len=strlen(tmp);
	if(total+len >BMAX) return NG;
	strcat(buff,tmp);
	//Connection Information
	total=strlen(buff);
	sprintf(tmp,"c=IN IP4 %s\r\n",hostid);
	len=strlen(tmp);
	if(total+len >BMAX) return NG;
	strcat(buff,tmp);
	//Time Description
	total=strlen(buff);
	sprintf(tmp,"t=%d %d\r\n",0,0);
	len=strlen(tmp);
	if(total+len >BMAX) return NG;
	strcat(buff,tmp);
	//Media Description
	total=strlen(buff);
	sprintf(tmp,"m=audio %d RTP/AVP 0\r\n",port);
	len=strlen(tmp);
	if(total+len >BMAX) return NG;
	strcat(buff,tmp);
	//Media Attribute 
	total=strlen(buff);
	sprintf(tmp,"a=rtpmap:0 PCMU/8000\r\n");
	len=strlen(tmp);
	if(total+len >BMAX) return NG;
	strcat(buff,tmp);
	//=====================================================
	//
	len=strlen(buff);
	sdp=(char *)malloc(strlen(buff));
	if(sdp==NULL) return NG;
	memset(sdp,0,len);
	memcpy(sdp,buff,len);
	*p=sdp;
	return len;
}


static int get_token(char **buff,char *token,int size)
{
	char *ptr;
	int l=0;
	char *next;
	int	ret;
	char	*start;
	if(buff==NULL) return NG;
	start=*buff;
	if(start==NULL||*start=='\0'||token==NULL) return NG;
	memset(token,0,size);
	next=NULL;
	for(ptr=start;*ptr;ptr++){
		if(*ptr=='\n'||*ptr=='\r'||*ptr==' '||*ptr=='='){
			if(*ptr=='\n') ret=SP_LF;
			if(*ptr=='\r') ret=SP_LF;
			if(*ptr==' ')  ret=SP_SP;
			if(*ptr=='='){
				ptr++;
				l++;
				ret=SP_EQ;
			}
			for(;*ptr;ptr++){
				if(*ptr!='\n'&& *ptr!='\r'&&*ptr!=' '){
					next=ptr;
					break;
				}
			}
			break;
		}else{ 
			l++;
		}
	}
	if(l>=size) return NG;
	memcpy(token,start,l);
	*buff=next;
//	printf("Token:%s | %d\n",token,ret);
//	if(ret==SP_LF) printf("--------------------------\n");
	return ret;
}



int AnalyzeSDP(char *sdp,int len,char *peerip,int *peerport)
{
	char	token[128];
	char	*ptr;
	int	flag=0;

	//Conection Information
	ptr=sdp;
	for(ptr=sdp;ptr!=NULL;){
		if(get_token(&ptr,token,100)==NG) 		return NG-0;
		if(strcmp(token,"c=")==0) {
			if(get_token(&ptr,token,100)==NG)	return NG-10;
			if(strcmp(token,"IN")!=0) 		return NG-20;
			if(get_token(&ptr,token,100)==NG)	return NG-30;
			if(strcmp(token,"IP4")!=0) 		return NG-40;
			if(get_token(&ptr,token,100)==NG)	return NG-50;
			strcpy(peerip,token);
			flag=1;
			break;
		}
	}
	if(flag==0) return NG-60;
	//Media Description
	ptr=sdp;
	flag=0;
	for(ptr=sdp;ptr!=NULL;){
		if(get_token(&ptr,token,100)==NG) 		return NG-70;
		if(strcmp(token,"m=")==0) {
			if(get_token(&ptr,token,100)==NG)	return NG-80;
			if(strcmp(token,"audio")!=0) 		return NG-90;
			if(get_token(&ptr,token,100)==NG)	return NG-100;
			*peerport=atoi(token);
			flag=1;
			break;
		}
	}
	if(flag==0) return NG-110;
	return OK;
}

