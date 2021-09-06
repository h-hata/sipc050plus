#include <stdio.h>
#include <time.h>
#include <string.h>

#define	LOG_FILE	"sipd"
#define	DEBUG_FILE	"debuglog"
#ifdef MAIN
static int debug=1;
#else
extern int debug;
#endif

#define DBG	if(debug==1){
#define	DEND	}
#define	BUFF_MAX	4096	

void logging(int level,char *mes)
{
	char	logname[BUFF_MAX+64];
	char	buff[BUFF_MAX+64];
	time_t	t;
	struct tm *tm;
	FILE	*fp;

	
	//Level
	//0:デバッグフラグがオンの時だけstdoutに表示
	//1:LOG_FILEにメッセージ格納(NARMAL)
	//2:LOG_FILEにメッセージ格納(WARNIG)
	//3:LOG_FILEにメッセージ格納(FATAL)



	buff[0]='\0';
	if(mes==NULL) return;
	time(&t);
	tm=localtime(&t);
	switch(level){
	case 0:
		sprintf(buff,"---:");
		break;
	case 1:
		sprintf(buff,"*--:");
		break;
	case 2:
		sprintf(buff,"**-:");
		break;
	case 3:
	case 4:
		sprintf(buff,"***:");
		break;
	case 9:
		break;	
	default:
		return;
	}
	sprintf(logname,"%04d/%02d/%02d %02d:%02d:%02d:",
		tm->tm_year+1900,
		tm->tm_mon+1,
		tm->tm_mday,
		tm->tm_hour,
		tm->tm_min,
		tm->tm_sec
		);
	strcat(buff,logname);
	strncat(buff,mes,BUFF_MAX);
	buff[sizeof(buff)-1]='\0';
	
	
DBG
	printf("%s\n",buff);
DEND
	if(level==0){
		return;
	}
	if(level==9){
		sprintf(logname,"%s-%04d%02d.log",
			DEBUG_FILE,(tm->tm_year+1900),tm->tm_mon+1);
	}else{
		sprintf(logname,"%s-%04d%02d.log",
			LOG_FILE,(tm->tm_year+1900),tm->tm_mon+1);
	}
	fp=fopen(logname,"a");
	if(fp==NULL) return;
	fprintf(fp,"%s\n",buff);
	fclose(fp);
}

#ifdef MAIN
main()
{
		
	logging(0,"Start up tcdrive");
	logging(1,"Start up tcdrive 000000");
	logging(2,"Start up tcdrive 92143091");
	logging(3,"Start up tcdrive 029430251");
}
#endif
