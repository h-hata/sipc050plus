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
#include "dtmf.h"

typedef struct dtmf_info_t {
	SESSION_TABLE	*ses;
	int		*indicator;
	char		*sequence;
	int		len;
}DTMF_INFO;

static int execute_fft(unsigned char *ptr);
static void *execute_dtmf(void *arg);
static char convchar(int key);


static void *execute_dtmf(void *arg)
{

	DTMF_INFO	*info;
	DTMF_INFO	dtmf;
	struct	timeval	tv;
	int	remain;
	int	i;
	int	fft_count=0;
	int	key;
	int	key_old=-1;
	int	len=0;
	char	ckey;

	memcpy(&dtmf,arg,sizeof(DTMF_INFO));
	info=&dtmf;
	*info->indicator=DTMF_EXE;
	for(i=0;i<5000;i++){
		//ɬ�׻����Ԥ�
		tv.tv_sec=0;
		tv.tv_usec=10000;//10�ߥ���
		select(32,NULL,NULL,NULL,&tv);
		//���Ϥ��٤��ǡ��������뤫��
		if(info->ses->update==-1) continue;
		if(info->ses->bufflock==1) continue;
		key=execute_fft(info->ses->buff);
		fft_count++;
		info->ses->update=-1;
		if(key==key_old){
			remain++;
			if(remain==4){
				//���֤�����
				if(key>=0){
					ckey=convchar(key);
					if(ckey=='#'){
						*info->sequence='\0';
						*info->indicator=DTMF_NORMAL_END;
						break;
					}
					*info->sequence++=ckey;
					len++;
					if(len>=info->len){
						*info->sequence='\0';
						*info->indicator=DTMF_NORMAL_END;
						break;
					}
				}else{
				//�����֥�������λ
				}
			}
		}else{
			remain=0;
			key_old=key;
		}
	}
	if(i==500)*info->indicator= DTMF_TIMEOUT;
	printf("FFT count=%d\n",fft_count);	
	return NULL;
}



void  DetectDTMF(SESSION_TABLE	*ses,int *indicator,char *sequence,int len)
{
	static DTMF_INFO	info;
	pthread_t	pt;

	info.ses=ses;
	info.indicator=indicator;
	info.sequence=sequence;
	info.len=len;
	
	pthread_create(&pt,NULL,execute_dtmf,&info);
	//pthread_detach(pt);
	return;
}


static char convchar(int key)
{
	if(key>=0 && key<=9){
		return '0'+key;
	}else if (key==10){
		return '*';
	}else if(key==11){
		return '#';
	}else{
		return '?';
	}
}

static int execute_fft(unsigned char *ptr)
{
	double	x[128];
	double	y[128];
	double	pow[128];
	double	p2;
	int	t;
	int	point0,point1,point2,point12;
	double	peak0,peak1,peak2,peak12;
	int	key;


	for(t=0;t<128;t++){
		x[t]=(double)ulaw2linear(*ptr++);
		y[t]=0;
	}
	//��ݤ���ά
	//FFT
	fft(1,7,x,y);
	//���ڥ��ȥ��ɾ��
	p2=peak1=peak12=peak2=peak0=0;
	point1=point12=point2=point0=0;
	//�ԡ�������Ƚ��
	for(t=0;t<64;t++){
		pow[t]=x[t]*x[t]+y[t]*y[t];
		p2+=pow[t];
		if(peak0<=pow[t]){
			peak0=pow[t];
			point0=t;
		}
		//���ԡ��������
		if(9<=t && t<=16){
			if(peak1<=pow[t]){
				peak12=peak1;
				point12=point1;
				peak1=pow[t];
				point1=t;
			}else{
				if(peak12<=pow[t]){
					peak12=pow[t];
					point12=t;
				}
			}
		}
		//���ԡ��������
		if(18<=t && t<=25){
			if(peak2<=pow[t]){
				peak2=pow[t];
				point2=t;
			}
		}
	}
	//�ԡ��������鲡���줿���������
	//11�ȣ��������˶ᤤ�Τǡ���������礭����
	//������������̯��Ƚ���Ԥ�
	if(point1==12 && point12==11){
		point1=11;
	}
	//Key Detect
	if(p2>5000000.0){
		if(point0 != point1 && point0 != point2){
			key=-7;
		}else{
			if(point1==11){
				if(point2==19||point2==20){
					key=1;
				}else if(point2==21||point2==22){
					key=2;
				}else if(point2==23||point2==24){
					key=3;
				}else{
					key=-2;
				}
			}else if(point1==12){
				if(point2==19||point2==20){
					key=4;
				}else if(point2==21||point2==22){
					key=5;
				}else if(point2==23||point2==24){
					key=6;
				}else{
					key=-3;
				}
			}else if(point1==14){
				if(point2==19){
					key=7;
				}else if(point2==21||point2==22){
					key=8;
				}else if(point2==23||point2==24){
					key=9;
				}else{
					key=-4;
				}
			}else if(point1==15){
				if(point2==19||point2==20){
					key=10;
				}else if(point2==21||point2==22){
					key=0;
				}else if(point2==23||point2==24){
					key=11;
				}else{
					key=-5;
				}
			}else{
				key=-6;
			}
		}
	}else{
		key=-1;
	}
	return key;
}

