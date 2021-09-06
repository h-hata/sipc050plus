#define	DTMF_IDLE		0	//実行中
#define	DTMF_EXE		1	//実行中
#define	DTMF_TIMEOUT		9
#define	DTMF_NORMAL_END		5
void  DetectDTMF(SESSION_TABLE	*ses,int *indicator,char *sequence,int len);
