/***********************************************************************\
	SIP Server	
	Date		Ver		Author		MemoRandom
	Jul 3,2002	1.0		Hiroaki Hata	Created
	(C) 2002 All Copyrights reserved. 
*************************************************************************/
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <wait.h>
#include <time.h>

#include "udp.h"
#include "sip.h"
#include "session.h"

#define	DEBUG if(debug==1){
#define DBG
#define	PR	printf

static	int	rtp_socket=0;

#define	ST_NONE		0
#define ST_STANDBY	1
#define	ST_RUNNING	2
#define	ST_SENT_BYE	3
#define	ST_NORMAL_END	4
#define	ST_ABORT	9
#define	ST_ERROR	8

#define	ST_SND_WAIT_ACK	0
#define	ST_SND_RUNNING	1
#define	ST_SND_RECV_BYE	2
#define	ST_SND_ABORT	3


#define	RECV_C	1
#define SEND_C	2
#define	BOTH_C	3



static unsigned char *CheckSoundPDU(unsigned char *data,size_t *len)
{
	unsigned char *ptr;
	unsigned int	rcc;
	ptr=(unsigned char *)data;
	rcc= *ptr & 0x0F;
	if(rcc==0){ 
		*len = *len-12;
	}
	return ptr+12;
}


void *execute_send_RTP(void *dumm)
{
#define	DSIZE	160
#define	DTIME	20	
#define RTP	12
	int	i,j,n;
	int	t;
	struct	timeval	tv;
	u_int32_t	*i32;
	u_int16_t	*i16;
	unsigned char	data[2000];
	char		host[32];
	short	pcm_base[400];
	unsigned char	*cptr;
	short	*sptr;
	short	sdata;
	int	conf_list[SESSION_MAX];


	printf("Transmit Thread started\n");
	//RTPヘッダを作る
	data[0]=0x80;//VER
	data[1]=0;//CC
	for(;;){
		//必要時間待つ
		tv.tv_sec=0;
		tv.tv_usec=DTIME*1000;
		select(32,NULL,NULL,NULL,&tv);
		//開設中の会議室一覧を作る
		for(j=0;j<SESSION_MAX;j++){
			conf_list[j]=0;
		}
		for(i=0;i<SESSION_MAX;i++){
			if(session[i].status!=ACTIVE_ST) continue;
			if(session[i].cnf==0) continue;
			for(j=0;conf_list[j]!=0 && j<SESSION_MAX;j++){
				if(conf_list[j]==session[i].cnf) break;
			}
			if(j<SESSION_MAX && conf_list[j]==0){
				conf_list[j]=session[i].cnf;
			}
		}
		//会議室ごとに音声合成する
		for(j=0;conf_list[j]!=0 && j<SESSION_MAX;j++){
			memset(pcm_base,0,160*2);
			//会議室全員の会話を合成する
			for(i=0;i<SESSION_MAX;i++){
				if(session[i].status!=ACTIVE_ST) continue;
				if(session[i].fp!=NULL) continue;
				if(session[i].cnf!=conf_list[j]) continue;
				if(session[i].bufflock==1) continue;
				session[i].bufflock=1;
				if(session[i].buffsize!=160) {
					session[i].bufflock=0;
					continue;
				}
				cptr=session[i].buff;
				sptr=pcm_base;
				for(t=0;t<160;t++){
					pcm_base[t]+=ulaw2linear(*cptr++);
				}
				session[i].bufflock=0;
			}
			for(i=0;i<SESSION_MAX;i++){
				//送信対象者ごとに送信処理をする
				if(session[i].status!=ACTIVE_ST) continue;
				if(session[i].fp!=NULL) continue;
				if(session[i].cnf!=conf_list[j]) continue;
				if(session[i].bufflock==1) continue;
				session[i].bufflock=1;
				if(session[i].buffsize!=160) {
					session[i].bufflock=0;
					continue;
				}
				//RTPヘッダを作る
				data[0]=0x80;//VER
				data[1]=0;//CC
				i16=(u_int16_t *)&data[2];
				*i16=htons(++session[i].sqc);//SQC
				i32=(u_int32_t *)&data[4];
				session[i].timing+=session[i].buffsize;
				*i32=htonl(session[i].timing);
				i32=(u_int32_t *)&data[8];
				*i32=htonl(getpid()+getpid()*16*16+i);

				//16bitリニアＰＣＭからμ-Lawに変換する
				cptr=session[i].buff;
				sptr=pcm_base;
				for(t=0;t<160;t++){
				//データを読む自分の声を消す
					sdata=*sptr-ulaw2linear(*cptr++);
					sptr++;
					data[RTP+t]=linear2ulaw(sdata);
				}
				ConvertIP4(session[i].rtpaddr,host);
				SendDataSocket(rtp_socket,host,session[i].rtpport,
						data,160+RTP);
				session[i].buffsize=0;
				session[i].bufflock=0;
			}
		}
		//トーキを送信する
		for(i=0;i<SESSION_MAX;i++){
			if(session[i].status!=ACTIVE_ST) continue;
			if(session[i].fp!=NULL){
				//読み込みバッファ初期化
				for(t=0;t<160;t++){
					pcm_base[t]=0x0080;
				}
				//ファイルから音声データを読み込み
				n=fread(pcm_base,2,160,session[i].fp);
				if(n<160) {
					if(session[i].rec_count!=0){
						fseek(session[i].fp,44,SEEK_SET);
					}else{
						fclose(session[i].fp);
						session[i].fp=NULL;
					}
				}
				if(n>0){
				//RTPヘッダを作る
					data[0]=0x80;//VER
					data[1]=0;//CC
					i16=(u_int16_t *)&data[2];
					*i16=htons(++session[i].sqc);//SQC
					i32=(u_int32_t *)&data[4];
					session[i].timing+=160;
					*i32=htonl(session[i].timing);
					i32=(u_int32_t *)&data[8];
					*i32=htonl(getpid()+getpid()*16*16+i);
					for(t=0;t<160;t++){
						data[RTP+t]=linear2ulaw(pcm_base[t]);
					}
					ConvertIP4(session[i].rtpaddr,host);
					SendDataSocket(rtp_socket,host,session[i].rtpport,
							data,160+RTP);
				}
			}
		}
		//ROOM 0には
		//無音を送信する
		for(i=0;i<SESSION_MAX;i++){
			if(session[i].status!=ACTIVE_ST) continue;
			if(session[i].fp!=NULL) continue;
			if(session[i].cnf!=0) continue;
			data[0]=0x80;//VER
			data[1]=0;//CC
			i16=(u_int16_t *)&data[2];
			*i16=htons(++session[i].sqc);//SQC
			i32=(u_int32_t *)&data[4];
			session[i].timing+=160;
			*i32=htonl(session[i].timing);
			i32=(u_int32_t *)&data[8];
			*i32=htonl(getpid()+getpid()*16*16+i);
			for(t=0;t<160;t++){
				data[RTP+t]=0xFF;
			}
			ConvertIP4(session[i].rtpaddr,host);
			SendDataSocket(rtp_socket,host,session[i].rtpport,data,160+RTP);
		}
	}
	return NULL;
}

void *execute_receive_RTP(void *dumm)
{

	unsigned char	data[2000];	
	size_t len;
	size_t	n;
	int	reason;
	unsigned char	*ptr;
	int	n_ip,n_port;
	int	idx;
	int	rtpport;

	printf("Receive Thread started\n");
	Get_SelfData(NULL,NULL,NULL,NULL,&rtpport);
	rtp_socket=InitializeUDP(rtpport);
	if(rtp_socket<=0) exit(1);

	for(;;){
		len=1800;
		n=RecvData(rtp_socket,data,&len,&n_ip,&n_port,5,&reason);
		if(n==0){
			continue;
		}else if(n<0){
			sleep(1);
		}else{
			ptr=CheckSoundPDU(data,&len);
			if(ptr!=NULL){
				//SearchPeer
				for(idx=0;idx<SESSION_MAX;idx++){
					if((session[idx].status!=VOID_ST)&&
					(session[idx].rtpaddr==n_ip)&&
					(session[idx].rtpport==n_port)&&
					(session[idx].bufflock==0)){
						session[idx].bufflock=1;
						memcpy(session[idx].buff,ptr,len);
						session[idx].buffsize=len;
						time(&session[idx].update);
						session[idx].bufflock=0;
						break;
					}
				}
			}
		}
	}
	return NULL;
}

