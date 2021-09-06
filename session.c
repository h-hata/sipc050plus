/***********************************************************************\
	SIP Server	
	Date		Ver		Author		MemoRandom
	Jul 3,2002	1.0		Hiroaki Hata	Created
	(C) 2002 All Copyrights reserved. 
*************************************************************************/
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

#define	DEBUG if(debug==1){
#define DBG
#include	"session.h"
#include	"play.h"

SESSION_TABLE	session[SESSION_MAX];
static int compare_session(MESSAGE *alice, MESSAGE *bob)
{
	if(strcmp(	alice->header.from.username,
			bob->header.from.username	)!=0) return 1;
	if(strcmp(	alice->header.callid,
			bob->header.callid		)!=0) return 2;
	return 0;
}

void InitSession(void)
{
	int i;

	for(i=0;i<SESSION_MAX;i++){
		session[i].status=VOID_ST;
	}
}

int EnterSession(SESSION_TABLE *ses,int room)
{
	int i;
	//最初の入室かどうかを検査
	
	for(i=0;i<SESSION_MAX;i++){
		if(session[i].status==VOID_ST) continue;
		if(session[i].cnf==room){
			break;
		}
	}
	if(i==SESSION_MAX){//新規
		PlaySoundFile(BGM,ses);
		ses->rec_count=-1;
		ses->cnf=room;
	}else{
		ses->cnf=room;
		for(i=0;i<SESSION_MAX;i++){
			if(session[i].status==VOID_ST) continue;
			if(session[i].cnf==room){
				session[i].rec_count=0;
				if(ses==&session[i]){
					PlaySoundFile(ROOM_ENTER,&session[i]);
				}else{
					PlaySoundFile(ROOM_ADD,&session[i]);
				}
			}
		}
	}	
	return 0;
}



int RegisterSession(MESSAGE *invite,int cnf,int direction,int rtpaddr,int rtpport)
{
	extern void ExecuteGuide(SESSION_TABLE *ses);
	time_t	t;
	int	i;

	time(&t);
	for(i=0;i<SESSION_MAX;i++){
		if(session[i].status==VOID_ST){
			session[i].status=ACTIVE_ST;
			session[i].sip_st=SIP_INVITED;
			session[i].invite=invite;
			session[i].direction=direction;
			session[i].cnf=cnf;
			session[i].rtpaddr=rtpaddr;
			session[i].rtpport=rtpport;
			time(&session[i].lifetime);
			ExecuteGuide(&session[i]);
			return OK;
		}
	}
	return  NG;
}



int DeleteSession(MESSAGE *mes)
{
	int	i;
	int	ret;
	char	logmes[BLEN];

	for(i=0;i<SESSION_MAX;i++){
		if(session[i].status!=VOID_ST){
			ret=compare_session(session[i].invite,mes);
			if(ret==0){
				sprintf(logmes,"BYE From: %s",mes->header.from.username);
				logging(2,logmes);
				printf("%s\n",logmes);
				free_message_buffer(session[i].invite);
				if(session[i].fp != NULL) {
					fclose(session[i].fp);
					session[i].fp=NULL;
				}
				memset(&session[i],0,sizeof(SESSION_TABLE));
				break;
			}
		}
	}
	return  OK;
}
