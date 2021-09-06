#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include <unistd.h>
#include	"sip.h"
#include	"udp.h"
//#include	"tcp/tcp.h"

#define	SLEN	128

/*************状態表示番号**********************/

#define	SIP_ST_INVALID		0	//初期化が必要な状態
#define	SIP_ST_IDLE		2	//初期化は完了したが、REGISTERが未完了
#define	SIP_ST_SENT_REG		3	//REGISTERを送信（時限状態）
#define	SIP_ST_SENT_REG0	4	//Expires=0 のREGISTERを送信した
#define	SIP_ST_REGISTER		5	//REGISTERが成功
#define	SIP_ST_REGISTERING	6	//REGISTERを再試行中
//-------------------------------発信状態


static	char	callid[CLEN];		//コールＩＤはランダムに作成
static	unsigned int	fromtag;
//-----------------------------------------------------------
static	char	username[SCLEN];		//自ＳＩＰＵＲＬ
static	char	userdomain[SCLEN];	//SIPURLのホスト部
//-----------------------------------------------------------
static	char	proxyip[SCLEN];		//サーバIP
static	int		proxyport;			//サーバポート
static	char	loginid[SCLEN];		//ユーザID（認証用）
static	char	passwd[SCLEN];		//ユーザパスワード（認証用）
static	time_t	last_sending=0;
static	int	expires=60;
static	unsigned int		seq=0;
static	int		reg_command=ON;

static	int	make_register_data_block(int onoff,MESSAGE **,PAUTH *auth);
static	double	qvalue=0.75;
static	int	reg_st=SIP_ST_IDLE;

static int TLS=0;

/*-------------------------------METHODS*/
#define	M_FLAG_ELSE			0
#define	M_FLAG_INVITE		1
#define	M_FLAG_ACK			2
#define	M_FLAG_OPTIONS		4
#define	M_FLAG_BYE			8
#define	M_FLAG_CANCEL		16
#define M_FLAG_REGISTER		32
#define M_FLAG_INFO			64
#define	M_FLAG_REFER_EXT	128
#define	M_FLAG_UPDATE		256
#define	M_FLAG_ACK_ERR		512
#define	M_FLAG_SUBSCRIBE	1024
#define	M_FLAG_NOTIFY		2048
#define	M_FLAG_REFER		4096
#define	M_FLAG_MESSAGE		8192
#define	M_FLAG_PRACK		16384
/*
static	unsigned int	register_allow=
	M_FLAG_ACK+
	M_FLAG_OPTIONS+
	M_FLAG_BYE+
	M_FLAG_CANCEL+
	M_FLAG_SUBSCRIBE+
	M_FLAG_MESSAGE+
	M_FLAG_NOTIFY+
	M_FLAG_INFO+
	M_FLAG_REFER;
*/
#define	TIMEUP	10

void SetQValue(double q)
{
	if(q>=0 && q<=1.0){
		qvalue=q;
	}else{
		qvalue=-1;
	}
}







int	SendRegister(int onoff,PAUTH *auth,int tls)
{
	MESSAGE *mes;
	char	buffer[1500];
	int	err;
	char	hostip[SLEN];
	int		hostport;			//自ポート
	char	host[SLEN];
	char	*ptr_o,*ptr_d;

	if(onoff==REFRESH && reg_command==OFF) {
		return SIP_E_OK;
	}
	if(onoff==ON||onoff==REFRESH){
		reg_command=ON;
	}else{//OFF CLEAR
		reg_command=OFF;
	}
	TLS=tls;
	//サーバ情報を取得
	Get_SelfData(hostip,&hostport,username,userdomain,NULL);
	Get_ProxyData(loginid,passwd,proxyip,&proxyport);	
	for(ptr_o=hostip,ptr_d=host;;ptr_o++){
		if(*ptr_o==':')continue;
		if(*ptr_o=='\0'){
			*ptr_d=*ptr_o;
			break;
		}
		*ptr_d++=*ptr_o;

	}
	if(onoff==ON || seq==0){
		//ＣＡＬＬＩＤを新しく生成する
		sprintf(callid,"%X%X%X%X@%s",rand(),rand(),rand(),rand(),host);
		//From Tagを生成する
		fromtag=rand()*100+rand()*10+rand();
	}
	seq++;
	if(seq>10000) seq=1;
	//送信パケットを作成する
	err=make_register_data_block(onoff,&mes,auth);
	//バッファを生成する
	err=MakeSendBuffer(mes,buffer);
	if(err!=OK){
		return SIP_E_ERROR;
	}
DEBUG
	printf("%s",buffer);
DEND
	//サーバに対して送信する
	//RetrySendData(serverip,serverport,buffer, strlen(buffer),M_REGISTER,mes->header.via->param.branch);
	SendData(proxyip,proxyport,(unsigned char*)buffer, strlen(buffer));
	time(&last_sending);
	//状態を変更する
	switch(onoff){
	case OFF:
	case CLEAR:
		reg_st=SIP_ST_SENT_REG0;
		break;
	case ON:
		reg_st=SIP_ST_SENT_REG;
	case REFRESH:
		break;
	}
	free_message_buffer(mes);
	return SIP_E_OK;
}

int	CheckRegister(void)
{

	time_t	t;
	unsigned int diff;
	int	rest;

	//状態を監視する
	time(&t);
	if(t<last_sending){
		diff=(0xFFFFFFFF-last_sending+t);
	}else{
		diff=(t-last_sending);
	}
	switch(reg_st)
	{
	case SIP_ST_SENT_REG://登録時
		if(diff > TIMEUP){
			expires=60;
			reg_st=SIP_ST_REGISTERING;
		}
		break;
	case SIP_ST_SENT_REG0://登録解除時
		if(diff > TIMEUP){
			reg_st=SIP_ST_IDLE;
		}
		break;
	case SIP_ST_REGISTER://既登録
		rest=expires/2-diff;
		if(rest<0)
			SendRegister(REFRESH,NULL,TLS);
		break;
	case SIP_ST_REGISTERING://リトライ中
		rest=expires/2-diff;
		if(rest<0)
			SendRegister(ON,NULL,TLS);
		break;
	default:
		break;
	}
	return 0;
}



static int	make_register_data_block(int onoff,MESSAGE **pmes,PAUTH *auth)
{
	//データを用意する

	MESSAGE *mes;
	VIA	*via;
	URI	*contact;
	char	self_ip[SCLEN];
	int	self_port;
	char	username[CLEN];

	//
	Get_SelfData(self_ip,&self_port,username,userdomain,NULL);
	//メモリ領域を確保する
	mes=(MESSAGE *)malloc(sizeof(MESSAGE));
	if(mes==NULL) return SIP_E_ERROR-100;
	memset(mes,0,sizeof(MESSAGE));
	//ファーストライン
	mes->start.type=REQUEST;
	mes->start.message=M_REGISTER;
	strcpy(mes->start.method,"REGISTER");
	strcpy(mes->start.proto,"SIP/2.0");
	strcpy(mes->start.requri.host,proxyip);
	mes->start.ver=2;
	
	//CallID
	strcpy(mes->header.callid,callid);
	//From
	strcpy(mes->header.from.username,username);
	strcpy(mes->header.from.host,userdomain);
	sprintf(mes->header.from.param.tag,"%u",fromtag);//tagを付加 2004/6/24
	//To
	strcpy(mes->header.to.username,username);
	strcpy(mes->header.to.host,userdomain);
	//CSeq
	mes->header.cseq.seq=seq;
	strcpy(mes->header.cseq.method,"REGISTER");
	//Via
	via=(VIA *)malloc(sizeof(VIA));
	if(via==NULL){
		free_message_buffer(mes);
		return NG-200;
	}
	memset(via,0,sizeof(VIA));
	strcpy(via->proto,"SIP");
	strcpy(via->ver,"2.0");
	if(TLS==1){
		strcpy(via->trans,"TCP");
		via->port=0;
	}else{
		strcpy(via->trans,"UDP");
		via->port=self_port;
	}
	strcpy(via->host,self_ip);
	sprintf(via->param.branch,"%s%X%X%X%XHH",MAGIC,rand(),rand(),rand(),rand());
	mes->header.via=via;
	//Contact
	if(TLS==0){
		contact=(URI *)malloc(sizeof(URI));
		if(contact==NULL){
			free_message_buffer(mes);
			return NG-200;
		}
		memset(contact,0,sizeof(URI));
		if(onoff!=CLEAR){ // ON or REFRESH or OFF
			strcpy(contact->username,username);
			strcpy(contact->host,self_ip);
			contact->port=self_port;
			if(onoff!=OFF){ //ON or REFRESH
				if(qvalue>=0.0 && qvalue<=1.0){
					contact->param.q = qvalue;
				}
			}
			strcpy(contact->param.transport,"udp");
		}
		mes->header.contact=contact;
	}
	//Content-Length
	mes->header.contentLength=0;
	//MaxFofwards
	mes->header.maxforwards=70;
	//Expires
	if(TLS==1){
		mes->header.expires=-1;
	}else if(onoff==OFF||onoff==CLEAR){
		mes->header.expires=0;
	}else{
		//mes->header.expires=Get_Expires();
		mes->header.expires=3600;
	}
	//UserAgent
	Get_Ver(mes->header.userAgent);
	//Authorization
	if(auth!=NULL){
		mes->header.wwwauthrz=auth;
	}
	//Allow
	//mes->header.allow=register_allow;
	*pmes=mes;
	return SIP_E_OK;

}

int RegisterResponse(MESSAGE *mes)
{
	PAUTH	*auth;
	static	int retry=0;
	//mesはフリーしてはいけません
	
	if(mes->header.cseq.seq!=seq){
		return -1;
	}
	if(strcmp(mes->header.callid,callid)!=0){
		return -1;
	}
	if(200<=mes->start.code && mes->start.code<=299){
		retry=0;
		if(reg_command==OFF){
			reg_st=SIP_ST_IDLE;
		}else{
			if(reg_st!=SIP_ST_REGISTER){
				printf("REGISTER OK\n");
				fflush(stdout);
				logging(1,"REGISTER OK");
				reg_st=SIP_ST_REGISTER;
			}
		}
		expires=3600;
		return 0;
	}else if(mes->start.code==401 || mes->start.code==407){
		if(retry==0){
			GetAuthorizeHeaderBlock(mes,&auth);
			retry++;
			if(reg_command==OFF){
				SendRegister(OFF,auth,TLS);
			}else{
				SendRegister(REFRESH,auth,TLS);
			}
		}else{
			reg_st=SIP_ST_REGISTERING;
			expires=120;
			retry=0;
		}
	}else{
		reg_st=SIP_ST_REGISTERING;
		expires=120;
		retry=0;
	}
	return 0;
}

