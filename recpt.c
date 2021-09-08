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
#include <pthread.h>

#include "udp.h"
#include "sip.h"
#include "session.h"
#include "fft.h"
#include "play.h"
#include "dtmf.h"

static void *execute_guide(void *dumm)
{
	SESSION_TABLE	*ses;
	char	keys[12];
	int	status=0;
	struct timeval tv;
	int	i=0;
	int	room;
	int	bye=1;
	
	ses=(SESSION_TABLE *)dumm;	
	printf("Guidance Thread started\n");

	//最初のメッセージを再生する
	if(ses->invite==NULL) return NULL;
	printf("Recpt thread treats %s call\n",ses->invite->header.from.username);
	PlaySoundFile(ROOM_INI,ses);
	sleep(7);
	for(i=0;i<2;i++){
		//ファイル再生指示
		for(i=0;i<1000;i++){
       		  	tv.tv_sec=0;
			tv.tv_usec=20000;//20ミリ秒
			select(0,NULL,NULL,NULL,&tv);
			if(ses->fp==NULL ){
				PlaySoundFile(ROOM_SEL,ses);
				break;
			}
		}
		//生成か加入か？
		//１文字入力
		DetectDTMF(ses,&status,keys,4);
		for(i=0;i<1000;i++){
			tv.tv_sec=0;
			tv.tv_usec=20000;//20ミリ秒
			select(0,NULL,NULL,NULL,&tv);
			if(status!=DTMF_EXE && status!=DTMF_IDLE){
					break;
			}
		}
		if(status==DTMF_NORMAL_END){
			room=atoi(keys);
				if(room>=1000 && room<=9999){
				EnterSession(ses,room);
				bye=0;
				break;
			}else{
				PlaySoundFile(ROOM_DECLINE,ses);
				sleep(2);
			}
		}else{
			PlaySoundFile(ROOM_DECLINE,ses);
			sleep(2);
		}
	}
	if(bye==1 && ses->invite!=NULL){
		SendBYE(ses->invite);
		DeleteSession(ses->invite);
		ses->invite=NULL;
	}
	printf("Guidance Thread end\n");
	return NULL;
}



void ExecuteGuide(SESSION_TABLE *ses)
{
	pthread_t	pt;

	pthread_create(&pt,NULL,execute_guide,ses);
	//pthread_detach(pt);
	return;
}


