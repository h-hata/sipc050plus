#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sip.h"

//static int authenticate_process(MESSAGE *mes,int fd,char *passwd);



int GetAuthorizeHeaderBlock(MESSAGE *mes,PAUTH **pa)
{

	PAUTH	*authrz;
	char	domain[SCLEN];
	char	id[SCLEN];
	char	passwd[SCLEN];
	char	proxy[SCLEN];
	int	ret;

	Get_SelfData(NULL,NULL,NULL,domain,NULL);
	Get_ProxyData(id,passwd,proxy,NULL);


	//Authorizationバッファエリアを確保する
	authrz=(PAUTH *)malloc(sizeof(PAUTH));

	if(authrz == NULL){
		logging(2,"Memory shortage for auth header");
		return NG;
	}
	*pa=authrz;
	//WWW-Authenticateヘッダをコピーする
	if(mes->header.wwwauthtc!=NULL){
		memcpy(authrz, mes->header.wwwauthtc ,sizeof(PAUTH));
	}else if (mes->header.authtc!=NULL){
		memcpy(authrz, mes->header.authtc ,sizeof(PAUTH));
	}else{
		free(authrz);
		return NG;
	}

	//uri
	if(strcmp(mes->header.cseq.method,"REGISTER")==0){
		sprintf(authrz->uri,"sip:%s",proxy);
	}else{
		sprintf(authrz->uri,"sip:%s@%s",mes->header.to.username,mes->header.to.host);
	}
	//username
	strcpy(authrz->username,id);
	//passwd
	strcpy(authrz->passwd,passwd);
	//nc
	strcpy(authrz->nc,"00000001");
	//cnonce
	sprintf(authrz->cnonce,"%d",rand());
	//method
	strcpy(authrz->method,mes->header.cseq.method);
	//algorithm
	strcpy(authrz->algorithm,"MD5");
	ret=CalcResponse(authrz);
	if(ret!=OK){
		free(authrz);
		logging(2,"Calc Digest Response Failed");
		return NG;	
	}
	return OK;
}


