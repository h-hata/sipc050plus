#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include "udp.h"
#include "sip.h"
#include "parser.h"

#define	MAGIC	"z9hG4bK"
static int analyze_displayname(char *buff,URI *url);
static int analyze_user_info(char *buff,URI *url);
static int analyze_host_port(char *buff,URI *url);
static int analyze_param_segment(char *buff,URIPARAM *param);
static int analyze_params(char *buff,URIPARAM *param);



static int analyze_displayname(char *buff,URI *url)
{

	char	*ptr;
	char	*start;


	for(;*buff==' ';){
		buff++;
	}	
	if(*buff=='"'){
		start=++buff;
		ptr=strchr(start,'"');
		if(ptr==NULL){
			return -10;
		}else{
			*ptr='\0';
			strcpy(url->display,start);
			return 0;
		}
	}
	
	if(strncmp(buff,"<sip:",5)==0){
		return 0;
	}
	if(strncmp(buff,"sip:",4)==0){
		return 0;
	}
	for(ptr=start=buff;*ptr;ptr++){
		if(*ptr=='<' || *ptr==' ' ){
			*ptr='\0';
			break;
		}
		if(strncmp(ptr,"sip:",4)==0){
			*ptr='\0';
			break;
		}
	}
	strcpy(url->display,start);
	return 0;
}

static int analyze_user_info(char *buff,URI *url)
{
	char	*start;
	char	*ptr;

	start=strstr(buff,"sip:");
	if(start==NULL){
		return -20;
	}
	start+=4;
	for(ptr=start;*ptr;ptr++){
		if(*ptr=='>' || *ptr==' ' ||*ptr==';'){
			*ptr='\0';
			break;
		}
	}

	//Is There any @
	ptr=strchr(start,'@');
	if(ptr!=NULL){
		*ptr='\0';
		//Is There any PASSWORD ?
		ptr=strchr(start,':');
		if(ptr!=NULL){
			*ptr='\0';
			ptr++;
			strcpy(url->password,ptr);
		}
		strcpy(url->username,start);
	}else{
		return -50;
	}
	return 0;
}


static int analyze_host_port(char *buff,URI *url)
{
	char	*start;
	char	*ptr;

	start=strstr(buff,"sip:");
	if(start==NULL){
		return -20;
	}
	start+=4;
	for(ptr=start;*ptr;ptr++){
		if(*ptr=='>' || *ptr==' ' ||*ptr==';'){
			*ptr='\0';
			break;
		}
	}

	//Is There any @
	ptr=strchr(start,'@');
	if(ptr!=NULL){
		start=++ptr;
	}
	/*
	    else{
		return -30;
		}
	*/
	//Is There any Port ?
	ptr=strchr(start,':');
	if(ptr!=NULL){
		*ptr='\0';
		ptr++;
		url->port=atoi(ptr);
	}
	strcpy(url->host,start);
	return 0;
}



static int analyze_param_segment(char *buff,URIPARAM *param)
{
	int	len;

	if(buff==NULL||*buff=='\0') return OK;
	if(strlen(buff)>CLEN) {
		logging(2,"param too long");
		logging(2,buff);
		return NG;
	}
	buff=SkipChars(buff,' ');
	if(strncmp(buff,PTAG,strlen(PTAG))==0){
		buff+=strlen(PTAG);
		strcpy(param->tag,buff);
	}else if(strncmp(buff,PUSER,strlen(PUSER))==0){
		buff+=strlen(PUSER);
		strcpy(param->user,buff);
	}else if(strncmp(buff,PBRANCH,strlen(PBRANCH))==0){
		buff+=strlen(PBRANCH);
		strcpy(param->branch,buff);
	}else if(strncmp(buff,PMADDR,strlen(PMADDR))==0){
		buff+=strlen(PMADDR);
		strcpy(param->maddr,buff);
	}else if(strncmp(buff,PTTL,strlen(PTTL))==0){
		buff+=strlen(PTTL);
		param->ttl=atoi(buff);
	}else if(strncmp(buff,PTRANSPORT,strlen(PTRANSPORT))==0){
		buff+=strlen(PTRANSPORT);
		strcpy(param->transport,buff);
	}else if(strncmp(buff,PMETHOD,strlen(PMETHOD))==0){
		buff+=strlen(PMETHOD);
		strcpy(param->method,buff);
	}else if(strncmp(buff,PLR,strlen(PLR))==0){
		param->lr=1;
	}else{
		len=sizeof(param->aux);
		len=sizeof(param->aux)-strlen(param->aux);
		if(len > (strlen(buff)+10)){
			strcat(param->aux,";");
			strcat(param->aux,buff);
		}else{
			logging(2,"param too long (2)");
			logging(2,buff);
			return NG;
		}
	}
	return OK;
}

static int shape_buffer(char *in_buff,char *out_buff)
{
	char	*ptr;

	*out_buff='\0';
	in_buff=SkipChars(in_buff,' ');
	if(*in_buff=='"'){
		//ダブルクォテーションを削除する
		in_buff++;
		ptr=strchr(in_buff,'"');
		if(ptr==NULL){
			logging(2,"double quate cannot be found");
			logging(2,in_buff);
			return NG;
		}else{
			*ptr='\0';
			strcpy(out_buff,in_buff);
			return OK;
		}
	}else{
		//末尾のスペースを削除する
		ptr=strchr(in_buff,' ');
		if(ptr!=NULL){
			*ptr='\0';
		}
		strcpy(out_buff,in_buff);
	}
	return OK;
}



static int analyze_pauth_segment(char *buff,PAUTH *param)
{
	int	len;
	char	abuff[CLEN];

	if(buff==NULL||*buff=='\0') return OK;
	if(strlen(buff)>CLEN) {
		logging(2,"pauth param too long");
		logging(2,buff);
		return NG;
	}
	buff=SkipChars(buff,' ');
	if(strncmp(buff,PAUTH_REALM,strlen(PAUTH_REALM))==0){
		buff+=strlen(PAUTH_REALM);
		shape_buffer(buff,abuff);
		strcpy(param->realm,abuff);
	}else if(strncmp(buff,PAUTH_USER,strlen(PAUTH_USER))==0){
		buff+=strlen(PAUTH_USER);
		shape_buffer(buff,abuff);
		strcpy(param->username,abuff);
	}else if(strncmp(buff,PAUTH_DOMAIN,strlen(PAUTH_DOMAIN))==0){
		buff+=strlen(PAUTH_DOMAIN);
		shape_buffer(buff,abuff);
		strcpy(param->domain,abuff);
	}else if(strncmp(buff,PAUTH_QOP,strlen(PAUTH_QOP))==0){
		buff+=strlen(PAUTH_QOP);
		shape_buffer(buff,abuff);
		strcpy(param->qop,abuff);
	}else if(strncmp(buff,PAUTH_OPAQUE,strlen(PAUTH_OPAQUE))==0){
		buff+=strlen(PAUTH_OPAQUE);
		shape_buffer(buff,abuff);
		strcpy(param->opaque,abuff);
	}else if(strncmp(buff,PAUTH_NONCE,strlen(PAUTH_NONCE))==0){
		buff+=strlen(PAUTH_NONCE);
		shape_buffer(buff,abuff);
		strcpy(param->nonce,abuff);
	}else if(strncmp(buff,PAUTH_CNONCE,strlen(PAUTH_CNONCE))==0){
		buff+=strlen(PAUTH_CNONCE);
		shape_buffer(buff,abuff);
		strcpy(param->cnonce,abuff);
	}else if(strncmp(buff,PAUTH_NC,strlen(PAUTH_NC))==0){
		buff+=strlen(PAUTH_NC);
		shape_buffer(buff,abuff);
		strcpy(param->nc,abuff);
	}else if(strncmp(buff,PAUTH_URI,strlen(PAUTH_URI))==0){
		buff+=strlen(PAUTH_URI);
		shape_buffer(buff,abuff);
		strcpy(param->uri,abuff);
	}else if(strncmp(buff,PAUTH_ALGORITHM,strlen(PAUTH_ALGORITHM))==0){
		buff+=strlen(PAUTH_ALGORITHM);
		shape_buffer(buff,abuff);
		strcpy(param->algorithm,abuff);
	}else if(strncmp(buff,PAUTH_STALE,strlen(PAUTH_STALE))==0){
		buff+=strlen(PAUTH_STALE);
		shape_buffer(buff,abuff);
		strcpy(param->stale,abuff);
	}else if(strncmp(buff,PAUTH_RESPONSE,strlen(PAUTH_RESPONSE))==0){
		buff+=strlen(PAUTH_RESPONSE);
		shape_buffer(buff,abuff);
		strcpy(param->response,abuff);
	}else{
		len=sizeof(param->aux);
		len=sizeof(param->aux)-strlen(param->aux);
		if(len > (strlen(buff)+10)){
			strcat(param->aux,";");
			strcat(param->aux,buff);
		}else{
			logging(2,"param too long (2)");
			logging(2,buff);
			return NG;
		}
	}
	return OK;
}


static int analyze_params(char *buff,URIPARAM *param)
{
	char *start;
	char *ptr;
	char *ptr1;
	int  ret=OK;

	for(start=buff;start!=NULL && *start!='\0' && ret==OK;start=ptr){
		ptr=strchr(start,';');
		if(ptr!=NULL){
			*ptr='\0';
			ptr1=strchr(start,'>');
			if(ptr1!=NULL){
				*ptr1='\0';
				ret=analyze_param_segment(start, param);
				return ret;
			}
			ptr++;
		}else {
			ptr=strchr(start,'>');
			if(ptr!=NULL){
				*ptr='\0';
				ptr++;
			}
		}
		ret=analyze_param_segment(start, param);
	}
	return ret;
}


int AnalyzePAUTH(char *pbuff,PAUTH *pauth)
{
#define	DIGEST	"Digest"
	char buff[CLEN];	
	int  ret=OK;
	char *start;
	char *ptr;

	if(pbuff == NULL || pauth==NULL){
		return NG;
	}
	strncpy(buff,pbuff,CLEN-1);
	buff[CLEN-1]='\0';
	ptr=SkipChars(buff,' ');
	if(strncmp(ptr,DIGEST,strlen(DIGEST))==0){
		ptr+=strlen(DIGEST);
		ptr=SkipChars(ptr,' ');
	}else{
		return NG;
	}

		
	for(start=ptr;start!=NULL && *start!='\0' && ret==OK ;start=ptr){
		ptr=strchr(start,',');
		if(ptr!=NULL){
			*ptr='\0';
			ptr++;
		}
		ret=analyze_pauth_segment(start, pauth);

	}
//	DisplayPAUTH(pauth);//Hata
	return ret;
}

		

int AnalyzeURI(char *buff,URI *url  )
{
	int	res;	
	char	*ptr;
	char	tmp[256];

	if(url==NULL||buff==NULL)
		return -1;
	//DisplayName
	strcpy(tmp,buff);
	res=analyze_displayname(tmp,url);
	//UserInfot
	strcpy(tmp,buff);
	res=analyze_user_info(tmp,url);
	//if(res!=0) return res;

	//HostPort
	strcpy(tmp,buff);
	res=analyze_host_port(tmp,url);
	if(res!=0) return res;

	//Analyze URI Params
	//>で文字列を止める
	strcpy(tmp,buff);
	ptr=strchr(tmp,'>');
	if(ptr!=NULL){
		*ptr='\0';
	}
	//セミコロンがあれば、パラメータがある
	ptr=strchr(tmp,';');
	if(ptr!=NULL){
		res=analyze_params(++ptr,&(url->param));
		if(res!=OK) return res;
	}

	//AUX Parameter
	strcpy(tmp,buff);
	ptr=strchr(tmp,'>');
	if(ptr!=NULL){
		if(NULL!=(strchr(++ptr,';'))){
			if(strlen(ptr)>CLEN){
				logging(2,"extra param too long");
				logging(2,ptr);
				return NG;
			}else{
				strcpy(url->aux,ptr);
			}
			//tag値を抽出
			if(strncmp(ptr,";tag=",strlen(";tag="))==0){
				ptr+=strlen(";tag=");
				strcpy(url->tag,ptr);
			}
		}
	}
	return OK;
}


int AnalyzeIntHeader(char *buff,int  *val)
{
	if(val==NULL||buff==NULL) return -1;
	*val = atoi(buff);
	return OK;
}

int AnalyzeCharHeader(char *buff, char *val)
{
	char	*ptr;
	if(buff==NULL||val==NULL)	return -1;
	ptr=SkipChars(buff,' ');
	if(strlen(ptr) >CLEN-1) return -2;
	strcpy(val,ptr);
	return 0;
}



int AnalyzeVia(char *buff,VIA *via)
{

	char	*ptr;
	char	*ptr1;
	char	tmp[SCLEN];
	int	len;
	int	ret;

	ptr=buff;
	len=SCLEN;
	ptr=SkipChars(ptr,' ');
	ptr=SeparateLex1(ptr,'/',tmp,&len);
	if(len>0 && len <SCLEN && ptr!=NULL){
		strcpy(via->proto,tmp);
	}else{
		return NG;
	}
	len=SCLEN;
	ptr=SeparateLex1(ptr,'/',tmp,&len);
	if(len>0 && len <SCLEN && ptr!=NULL){
		strcpy(via->ver,tmp);
	}else{
		return NG-1;
	}
	len=SCLEN;
	ptr=SeparateLex1(ptr,' ',tmp,&len);
	if(len>0 && len <SCLEN && ptr!=NULL){
		strcpy(via->trans,tmp);
	}else{
		return NG-2;
	}
	ptr=SkipChars(ptr,' ');
	len=SCLEN;
	//ポート番号はあるか？
	ptr1=SeparateLex1(ptr,':',tmp,&len);
	if(ptr1!=NULL){
		ptr=ptr1;	
		if(len>0 && len <SCLEN ){
			//ポート番号がある
			strcpy(via->host,tmp);
			ptr1=SeparateLex1(ptr,';',tmp,&len);
			//パラメータまであるか 
			if(ptr1!=NULL){
				if(len>0 && len <SCLEN){
					//ポート番号はありパラメータもある 
					via->port=atoi(tmp);
				}else{
					return NG-3;
				}
			}else{
				//ポート番号はあるがパラメータはない 
				via->port=atoi(ptr);
			}
			ptr=ptr1;
		}else{
			return NG-4;
		}
	}else{
		//ポート番号がない 
		via->port=SIP_PORT;
		ptr1=SeparateLex1(ptr,';',tmp,&len);
		//パラメータまであるか 
		if(len>0 && len <SCLEN && ptr1!=NULL){
			//ポート番号はありパラメータもある 
			strcpy(via->host,tmp);
		}else{
			strcpy(via->host,ptr);
		}
		ptr=ptr1;
	}
	//パラメータの解析 
	if(ptr!=NULL) {	
		ret=analyze_params(ptr,&(via->param));
		if(ret!=OK){
			return NG-4;
		}
	}
	return OK;	
}

int AnalyzeCSeq(char *buff,CSEQ *cseq)
{
	char	tmp[2][128];
	char	*ptr[2];
	ptr[0]=tmp[0];ptr[1]=tmp[1];
	SeparateLex(buff,' ',ptr,2);
	cseq->seq=atoi(tmp[0]);
	strcpy(cseq->method,tmp[1]);
	return 0;	
}


int AddVia(VIA **top,unsigned char *hash)
{
	VIA	*ptr;
	char	branch[256];
	char	hostid[256];
	int	hostport;

	//topからはじまるVIAセリーの一番最初に自サーバ情報を追加する
	//一番最後のVIAを捕まえる
	//
	//VIAエリアを確保する

	Get_SelfData(hostid,&hostport,NULL,NULL,NULL);

	ptr=(VIA *)malloc(sizeof(VIA));
	if(ptr==NULL){
		logging(1,"memory short (234)");
		return NG;
	}
	memset(ptr,0,sizeof(VIA));
	//情報設定
	strcpy(ptr->proto,"SIP");
	strcpy(ptr->ver,"2.0");
	strcpy(ptr->trans,"UDP");
	strcpy(ptr->host,hostid);
	ptr->port=hostport;
	sprintf(branch,"%s%s",MAGIC,hash);
	*branch='\0';	
	strcpy(ptr->param.branch,branch);
	//追加する
	if(NULL==*top){
		*top=ptr;
	}else{
		ptr->next=*top;
		*top=ptr;
	}
	return OK;
}

int AddURI(URI **top)
{
	URI	*ptr;
	char	hostid[256];
	int	hostport=5060;

	//topからはじまるURIセリーの一番最初に自サーバ情報を追加する
	//
	//URIエリアを確保する
	ptr=(URI *)malloc(sizeof(URI));
	if(ptr==NULL){
		logging(1,"memory short (2345)");
		return NG;
	}
	memset(ptr,0,sizeof(URI));
	//追加する
	if(NULL==*top){
		*top=ptr;
	}else{
		ptr->next=*top;
		*top=ptr;
	}
	//情報設定
	strcpy(ptr->host,hostid);
	ptr->port=hostport;
	sprintf(ptr->username,"boofoo%d",getpid());
	return OK;
}

int SearchVia(VIA **top,char *host,int *port)
{
	VIA	*ptr;
	char	hostid[256];

	//VIA topが自分であるかどうか検査する
	ptr=*top;
	if (ptr==NULL){
		logging(2,"Not found Via in Response(344)");
		return NG;
	}
	Get_SelfData(hostid,NULL,NULL,NULL,NULL);
	//自サーバ宛かどうか検査する
	if(strcmp(hostid,ptr->host)==0){
		//自サーバ宛である
		*top=ptr->next;
		//最後尾VIAを消去する
		free(ptr);
		ptr=*top;
	}
	strcpy(host,ptr->host);
	*port=ptr->port;
	return OK;
}

int DeleteURI(URI **top)
{
	URI	*ptr;
	char	hostid[CLEN];


	if(top==NULL){
		logging(3,"Invlid parameter BUG(Delete URI)");
		return NG;
	}
	Get_SelfData(hostid,NULL,NULL,NULL,NULL);
	
	//URI topが自分であるかどうか検査する
	ptr=*top;
	if (ptr==NULL){
		return OK;
	}
	//自サーバ宛かどうか検査する
	if(strcmp(hostid,ptr->host)==0){
		//自サーバ宛である
		*top=ptr->next;
		//最後尾VIAを消去する
		free(ptr);
	}
	return OK;
}

void DisplayURI(int level,URI *uri)
{

	printf("DisplayName:%s\n",uri->display);
	printf("UserName:%s\n",uri->username);
	printf("Password:%s\n",uri->password);
	printf("Host:%s\n",uri->host);
	printf("Port:%d\n",uri->port);
	printf("tag:%s\n",uri->param.tag);
	printf("maddr:%s\n",uri->param.maddr);
	printf("branch:%s\n",uri->param.branch);
	printf("ttl:%d\n",uri->param.ttl);
	printf("lr:%d\n",uri->param.lr);
	printf("transport:%s\n",uri->param.transport);
	printf("user:%s\n",uri->param.user);
	printf("method:%s\n",uri->param.method);
	printf("param.aux:%s\n",uri->param.aux);
	printf("tag:%s\n",uri->tag);
	printf("aux:%s\n",uri->aux);
	printf("------------------------------\n");
}

void DisplayPAUTH(PAUTH *pauth)
{
	if(pauth==NULL) return;
	printf("realm=%s\n",pauth->realm);
	printf("domain=%s\n",pauth->domain);
	printf("qop=%s\n",pauth->qop);
	printf("opaque=%s\n",pauth->opaque);
	printf("nonce=%s\n",pauth->nonce);
	printf("cnonce=%s\n",pauth->cnonce);
	printf("nc=%s\n",pauth->nc);
	printf("uri=%s\n",pauth->uri);
	printf("username=%s\n",pauth->username);
	printf("algorithm=%s\n",pauth->algorithm);
	printf("stale=%s\n",pauth->stale);
	printf("response=%s\n",pauth->response);
	printf("aux=%s\n",pauth->aux);
}




#ifdef TEST
static void trim(char *p)
{
	for(;*p;p++){
		if(*p==0x0d||*p==0x0a){
			*p='\0';
			break;
		}
	}
}




static void test_URI(int argc ,char **argv)
{

	char	buff[256];
	FILE	*fp;
	URI	url;
	int	res;

	if(argc<2){
		exit(0);
	}
	fp=fopen(argv[1],"r");
	if(fp==NULL){
		exit(0);
	}
	for(;fgets(buff,200,fp);){
		trim(buff);
		memset(&url,0,sizeof(URI));
		printf("------------------------\n");
		printf("%s\n",buff);
		printf("----\n");
		res=AnalyzeURI(buff,&url);
		printf("res=%d\n",res);
		if(res==OK){
			DisplayURI(1,&url);
		}
	}
	fclose(fp);
}

static void testVIA(int argc,char **argv)
{	
	VIA	via;
	int ret;

	char	mes[]="SIP/2.0/UDP 10.1.2.3:5060;branch=sidugy9suga;received=192.168.10.2";
		
	printf("Original mes=%s\n",mes);
	memset(&via,0,sizeof(VIA));
	ret=AnalyzeVia(mes,&via);
	printf("ret=%d\n",ret);
	printf("proto=%s\n",via.proto);
	printf("ver=%s\n",via.ver);
	printf("trans=%s\n",via.trans);
	printf("host=%s\n",via.host);
	printf("port=%d\n",via.port);
	printf("branch=%s\n",via.param.branch);
}


main(int argc,char **argv)
{
	testVIA(argc,argv);	
	//test_URI(argc,argv);
}
#endif
