#include <stdio.h>
#include <time.h>
#include "sip.h"
#include "session.h"
#include "play.h"




void PlaySoundFile(char *filename,SESSION_TABLE *ses)
{

	FILE	*fp;
	if(ses->fp!=NULL){
		fclose(ses->fp);
		ses->fp=NULL;
	}

	fp=fopen(filename,"r");
	if(fp==NULL){
		return;
	}
	fseek(fp,44,SEEK_SET);
	ses->fp=fp;
	return;

}
