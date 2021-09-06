/***********************************************************************\

	SIP Server	

	Date		Ver		Author		MemoRandom
	Jul 3,2002	1.0		Hiroaki Hata	Created

	(C) 2002 All Copyrights reserved. 
*************************************************************************/
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include "sip.h"
#include "parser.h"
#define	DEBUG if(debug==1){
#define DEND	}

#ifdef MAIN 
int debug=1;
#endif



static char rfc2396[]=
	";/?:@&=+$,<>#\"";
/*
static char rfc3986[]=
	":/?#[]@!$&'()*+,;=";
	
*/


void EncodeEscapeString(char *pinp,char *poutp)
{
	char	*eptr;

	if(pinp==NULL||poutp==NULL) return;
	for(;;pinp++){
		//特殊文字区間検査
		if((*pinp <= '!' && *pinp <= '/')||(*pinp <= ':' && *pinp <= '@')){
			for(eptr=rfc2396;*eptr!='\0';eptr++){
				if(*eptr==*pinp){
					//エスケープ対象文字
					sprintf(poutp,"%%%02X",*pinp);
					poutp+=3;
					break;
				}
			}
			if(*eptr=='\0'){
				//特殊文字区間だがエスケープ該当外
				*poutp++ = *pinp;
			}
		}else{
			//特殊文字区間外
			*poutp++ = *pinp;
		}
		if(*pinp=='\0') break;
	}
	return;
}

void TrimChar(char *ptr,char c)
{
	char *marker=NULL;

	for(;*ptr;ptr++){
		if(*ptr==c){
			if(marker==NULL){
				marker=ptr;
			}else{
			}
		}else{
			marker=NULL;
		}
	}
	if(marker!=NULL){
		*marker='\0';
	}
}


char *SkipChars(char *ptr,char c)
{
	for(;*ptr==c;ptr++){
	}
	return ptr;
}

char *SeparateLex1(char *buff,char c,char *optr,int *plen)
{
	char	*ptr;
	int	i=0;

	ptr=buff;
	if(buff==NULL)return 0;
	for(ptr=buff;;ptr++){
		if(*ptr==c){
			++ptr;
			break;
		}else if(*ptr=='\0'){
			ptr=NULL;
			break;
		}
		i++;
	}

	if(i==0){
		*plen=0;
	}else if( i < *plen){
		memcpy(optr,buff,i);
		optr[i]='\0';
		*plen=i;
	}else{
		*plen=-1;
	}
	return ptr;
}


int SeparateLex(char *buff,char c,char **optr,int n)
{
	int i=0;
	char *sptr;
	char *ptr;
	char *eot;

	sptr=ptr=SkipChars(buff,c);
	if(*ptr=='\0'){
		return 0;
	}
	for(;;ptr++){
		if(*ptr=='\0'){
			strcpy(optr[i],sptr);
			return i++;
		}
		if(*ptr==c){
			eot=ptr;
			ptr=SkipChars(ptr,c);
			*eot='\0';
			strcpy(optr[i],sptr);
			i++;
			if(i==n||*ptr=='\0') return i;	
			sptr=ptr;
		}
	}
}



int copy_message_buffer(MESSAGE *dst,MESSAGE *src)
{
	VIA	*v;
	VIA	*vnext;
	VIA	*vs;
	URI	*url;
	URI	*urlnext;
	URI	*urls;

//	PAUTH	*pauth;

	//一旦全域をコピーする
	memcpy(dst,src,sizeof(MESSAGE));

	//ポインターは新しい領域を確保してから更新
	//Copy buffers for VIA chaining 
	//=========================================VIA
	vnext=NULL;
	for(v=src->header.via;v!=NULL;){
		vs=(VIA *)malloc(sizeof(VIA));
		if(vs==NULL) return NG;
		memcpy(vs,v,sizeof(VIA));
		vs->next=NULL;
		if(vnext==NULL) {
			dst->header.via=vs;
		}else{
			vnext->next=vs;
		}
		vnext=vs;
		v=v->next;
	} 
	//=========================================ROUTE
	//Free buffer for Route  chaining buffer
	urlnext=NULL;
	for(url=src->header.route;url!=NULL;){
		//領域を確保
		urls=(URI *)malloc(sizeof(URI));
		if(urls==NULL) return NG;
		//内容をコピー
		memcpy(urls,url,sizeof(URI));
		//ネクストポインターを切る
		urls->next=NULL;
		//最初のレコードなら本体に指させる
		if(urlnext==NULL){
			dst->header.route=urls;
		}else{
			//２個目以降なら前のレコードに指させる
			urlnext->next=urls;
		}
		//前のレコードにする
		urlnext=urls;
		//次のレコード
		url=url->next;
	}
	//=========================================RECORD-ROUTE
	//Free buffer for Record-Route  chaining buffer
	urlnext=NULL;
	for(url=src->header.recordroute;url!=NULL;){
		//URIエリアを確保する
		urls=(URI *)malloc(sizeof(URI));
		if(urls==NULL) return NG;
		//コピーする
		memcpy(urls,url,sizeof(URI));
		//次へのチェーンを止める
		urls->next=NULL;
		//最初のレコードならヘッダからチェーンする
		if(urlnext==NULL){
			dst->header.recordroute=urls;
		}else{
			//前のレコードからチェーンする
			urlnext->next=urls;
		}
		//前のレコードにする
		urlnext=urls;
		url=url->next;
	}
	//Auth
	dst->header.authtc=NULL;
	dst->header.authrz=NULL;
	dst->header.wwwauthrz=NULL;
	dst->header.wwwauthtc=NULL;
	//=========================================CONTACT
	//Contact
	//Free buffer for Contact  chaining 
	dst->header.contact=NULL;
	/*
	urlnext=NULL;
	for(url=src->header.contact;url!=NULL;){
		//URIエリアを確保する
		urls=(URI *)malloc(sizeof(URI));
		if(urls==NULL) return NG;
		//コピーする
		memcpy(urls,url,sizeof(URI));
		//次へのチェーンを止める
		urls->next=NULL;
		//最初のレコードならヘッダからチェーンする
		if(urlnext==NULL){
			dst->header.contact=urls;
		}else{
			//前のレコードからチェーンする
			urlnext->next=urls;
		}
		//前のレコードにする
		urlnext=urls;
		url=url->next;
	}
	*/
	//=========================================GENERAL
	//Free buffer for General  chaining buffer
	dst->header.general=NULL;
	/*
	for(g=src->header.general;g!=NULL;){
		//エリアを確保する
		gs=(GENERAL *)malloc(sizeof(GENERAL));
		if(gs==NULL) return NG;
		//コピーする
		memcpy(gs,g,sizeof(GENERAL));
		//次へのチェーンを止める
		gs->next=NULL;
		//最初のレコードならヘッダからチェーンする
		if(gnext==NULL){
			dst->header.general=gs;
		}else{
			//前のレコードからチェーンする
			gnext->next=gs;
		}
		//前のレコードにする
		gnext=gs;
		g=g->next;
	}
	*/ 
	//Contents
	dst->contents=NULL;
	dst->header.contentLength=0;
	dst->header.contentType[0]='\0';
	//Buffer
	dst->buff=NULL;
	return OK;
}

void free_message_buffer(MESSAGE *mes)
{
	VIA	*v;
	VIA	*vnext;
	URI	*url;
	URI	*urlnext;
	GENERAL	*g;
	GENERAL	*gnext;

	if(mes==NULL) return;
	//Free buffer for VIA chaining buffer
	for(v=mes->header.via;v!=NULL;){
		vnext=v->next;
		free(v);
		v=vnext;
	} 
	//Free buffer for Contact  chaining buffer
	for(url=mes->header.contact;url!=NULL;){
		urlnext=url->next;
		free(url);
		url=urlnext;
	}
	//Free buffer for Route  chaining buffer
	for(url=mes->header.route;url!=NULL;){
		urlnext=url->next;
		free(url);
		url=urlnext;
	}
	//Free buffer for Record-Route  chaining buffer
	for(url=mes->header.recordroute;url!=NULL;){
		urlnext=url->next;
		free(url);
		url=urlnext;
	}
	//Auth's
	if(mes->header.authtc!=NULL){
		free(mes->header.authtc);
		mes->header.authtc=NULL;
	}
	if(mes->header.authrz!=NULL){
		free(mes->header.authrz);
		mes->header.authrz=NULL;
	}
	if(mes->header.wwwauthtc!=NULL){
		free(mes->header.wwwauthtc);
		mes->header.wwwauthtc=NULL;
	}
	if(mes->header.wwwauthrz!=NULL){
		free(mes->header.wwwauthrz);
		mes->header.wwwauthrz=NULL;
	}

	//Free buffer for General  chaining buffer
	for(g=mes->header.general;g!=NULL;){
		gnext=g->next;
		free(g);
		g=gnext;
	} 
	//Contents
	if(mes->contents!=NULL){
		free(mes->contents);
		mes->contents=NULL;
	}
	//Buffer
	if(mes->buff!=NULL){
		free(mes->buff);
		mes->buff=NULL;
	}
	free(mes);
}
#if 0
int CalcHash(MESSAGE *mes,unsigned char *hash)
{
#define	BUFF_SIZ	9182
	//unsigned char	in_buff[BUFF_SIZ];
	char	in_buff[BUFF_SIZ];
	int	i;
	char	seq[8];

	if(mes==NULL || hash==NULL){
		return NG;
	}
	in_buff[0]='\0';
	strcpy(in_buff,mes->header.to.username);
	strcat(in_buff,mes->header.to.host);
	if(strlen(in_buff) + strlen(mes->header.from.username) > BUFF_SIZ)
		return NG;
	strcat(in_buff,mes->header.from.username);
	if(strlen(in_buff) + strlen(mes->header.from.host) > BUFF_SIZ)
		return NG;
	strcat(in_buff,mes->header.from.host);
	if(strlen(in_buff) + strlen(mes->header.from.tag) > BUFF_SIZ)
		return NG;
	strcat(in_buff,mes->header.from.tag);
	if(strlen(in_buff) + strlen(mes->header.callid) > BUFF_SIZ)
		return NG;
	strcat(in_buff,mes->header.callid);
	if(strlen(in_buff) + strlen(mes->header.cseq.method) > BUFF_SIZ)
		return NG;
	strcat(in_buff,mes->header.cseq.method);
	sprintf(seq,"%d",mes->header.cseq.seq);
	if(strlen(in_buff) + strlen(seq) > BUFF_SIZ)
		return NG;
	strcat(in_buff,seq);
DEBUG
	printf("HASH:%s\n",in_buff);
DEND
	MD5(hash,(unsigned char *)in_buff,strlen(in_buff));
DEBUG
	i=0;
	printf("HASH:");
	for(i=0;i<HASH_LEN;i++){
		printf("%02X",hash[i]);
	}
	printf("\n");

DEND
	return OK;
}
#endif


static void CvtHex(unsigned char *hash_bin, unsigned char *hash_asc)
{
	unsigned short i;
	unsigned char	j;

	for(i=0;i<HASH_LEN;i++){
		j=(hash_bin[i]>>4)&0xf;
		if(j<=9)
			hash_asc[i*2]=(j+'0');
		else
			hash_asc[i*2]=(j+'a'-10);
		j=hash_bin[i]&0xf;
		if(j<=9)
			hash_asc[i*2+1]=(j+'0');
		else
			hash_asc[i*2+1]=(j+'a'-10);
	}
	hash_asc[HASH_LEN*2]='\0';
}


static void digest_HA1(char *hash,char *user,char *realm,char *passwd)
{
	unsigned char hash_bin[HASH_LEN];
	char	str[CLEN];
	sprintf(str,"%s:%s:%s",user,realm,passwd);
	printf("%s\n",str);
	MD5((const unsigned char *)str,strlen(str),hash_bin);
	CvtHex(hash_bin,hash);
	printf("HA1:%s\n",hash); //Hata
	return ;
}
static void digest_HA2(char *hash,char *method,char *uri)
{
	unsigned char hash_bin[HASH_LEN];
	char	str[CLEN];
	
	sprintf(str,"%s:%s",method,uri);
	printf("%s\n",str);
	MD5((const unsigned char *)str,strlen(str),hash_bin);
	CvtHex(hash_bin,hash);
	printf("HA2:%s\n",hash); //Hata
	return ;
}

static void digest_response(unsigned char *hash,
		char *nonce,char *nc,char *cnonce,char *qop,
		char *HA1, char *HA2)
{
	unsigned char hash_bin[HASH_LEN];
	char str[BLEN];
	if(qop!=NULL && strcmp(qop,"auth")==0){
		sprintf(str,"%s:%s:%s:%s:%s:%s",HA1,nonce,nc,cnonce,qop,HA2);
	}else{
		sprintf(str,"%s:%s:%s",HA1,nonce,HA2);
	}
	printf("%s\n",str);
	MD5((const unsigned char *)str,strlen(str),hash_bin);
	CvtHex(hash_bin,hash);
	printf("Response:%s\n",hash); //Hata
	return ;
}




int CalcResponse(PAUTH *p)
{
	unsigned char	HA1[36];
	unsigned char	HA2[36];
	unsigned char	response[36];

	if(p==NULL){
		logging(2,"CalcResponse:param error");
		return NG;
	}
	digest_HA1(HA1,p->username,p->realm,p->passwd);
	digest_HA2(HA2,p->method,p->uri);
	digest_response(response,p->nonce,p->nc,p->cnonce,p->qop,HA1,HA2);
	memcpy(p->response,response,strlen((char *)response));
	return OK;
}




/************************/

#ifdef MAIN
main()
{
	char	*username="SH373NDO";
	char	*nonce="1159765677";
	char	*realm="com-voip.jp";
	char	*passwd="APlvwwHU";
	char	*uri="sip:kar-f2fcp.050plus.com";
	char	*cnonce="41";
	char	nc[9]="00000001";
	char	*qop="";
	char	*method="REGISTER";
	char	HA1[36];
	char	HA2[36];
	char	response[36];

	digest_HA1(HA1,username,realm,passwd);
	printf("HA1:%s\n",HA1);
	digest_HA2(HA2,method,uri);
	printf("HA2:%s\n",HA2);
	digest_response(response,nonce,nc,cnonce,qop,HA1,HA2);
	printf("response:%s\n",response);
}


#endif
