/***********************************************************************\

	SIP 	

	Date		Ver		Author		MemoRandom
	Jul 3,2002	1.0		Hiroaki Hata	Created
	Jul 3,2021	2.0		Hiroaki Hata  modified	

	(C) 2002-2021 All Copyrights reserved. 
*************************************************************************/

#define DEBUG	if(debug==1){
#define FORE	if(fore==1){
#define DEND	}


#define	ON			1
#define	OFF			0
#define	CLEAR			2
#define	REFRESH			3
#define	OK			0
#define	NG			-1


#define	YES	1
#define NO	0	
#define	OK	0
#define	NG	-1
#define	SCLEN		80	
#define	CLEN		1024	
#define	BLEN		 4096	
#define	USER_MAX	512
#define	DOMAIN_MAX	16
#define MAX_BUFF	4096	
#define	REG_NG		-1
#define	REG_ADD		1
#define	REG_RENEW	2
#define	REG_DEL		3
#define	DB_WATCH	60
#define	RECV_TIME_OUT	5
#define	PROCESS_TIME_OUT	60	
#define	SIP_PORT	5060
#define HASH_LEN	16	

#define CRLF		1
#define	BRACE		2
#define	DISPLAYNAME	4

#define SIP_E_OK 0
#define SIP_E_ERROR -10000
	
extern int debug;
extern int fore;


#define SESSION 	-1000

#define	MAGIC		"z9hG4bK"
#define	REQUEST		1
#define	RESPONSE	2

/*-------------------------------METHODS*/
#define	M_INVITE	1
#define	M_ACK		2
#define	M_OPTIONS	3
#define	M_BYE		4
#define	M_CANCEL	5
#define M_REGISTER	6
#define M_INFO	7

#define	M_SUBSCRIBE	101
#define	M_MESSAGE	111
/*--------------------------------Error Code */
#define	E_OK		200
#define	E_TRYING	100
#define	E_RINGING	180
#define	E_BADREQ	400
#define	E_UNAUTH	401
#define	E_NOTFOUND	404
#define	E_NOTALLOW	405
#define	E_NOTACCEPT	406
#define E_PROXYAUTH	407
#define	E_TIMEOUT	408
#define	E_GONE		410
#define	E_MEDIATYPE	415
#define	E_URI		416
#define	E_TRANSACTION	481
#define	E_MANYHOP	483
#define	E_BUSY		486
#define	E_REQTERM	487
#define	E_SERVER	500
#define	E_IMPLEMENT	501
#define	E_GATEWAY	502
#define	E_VERSION	505



/*--------------------------------HEADER*/
//Mandatory
#define	CALLID_H	1
#define	CSEQ_H		2
#define	TO_H		3
#define	FROM_H		4
#define	VIA_H		5
/*----------------------------------------*/
//Optional
#define	CONTACT_H	6
#define	EXPIRES_H	7
#define	CONTENTENC_H	8
#define	CONTENTTYPE_H	9
#define	CONTENTLEN_H	10
#define	USERAGENT_H	11
#define	MAXFORWARDS_H	12
#define	ROUTE_H		13
#define	RECORDROUTE_H	14
#define PROXY_AUTHRZ_H	15
#define PROXY_AUTHTC_H	16
#define WWW_AUTHTC_H	17
#define ELSE_H		9999
#define	Blank		8888

/*--------------------------------Params*/
#define	PTAG		"tag="
#define	PTTL		"ttl="
#define	PMADDR		"maddr="
#define	PTRANSPORT	"transport="
#define	PMETHOD		"method="
#define	PUSER		"user="
#define	PBRANCH		"branch="
#define	PLR		"lr"
//-------------------------------PAuth
#define	PAUTH_REALM	"realm="
#define	PAUTH_USER	"username="
#define	PAUTH_DOMAIN	"domain="
#define PAUTH_QOP	"qop="
#define PAUTH_OPAQUE	"opaque="
#define PAUTH_NONCE	"nonce="
#define PAUTH_CNONCE	"cnonce="
#define	PAUTH_NC	"nc="
#define	PAUTH_URI	"uri="
#define	PAUTH_ALGORITHM	"algorithm="
#define	PAUTH_STALE	"stale="
#define	PAUTH_RESPONSE	"response="

/*--------------------------------TYPEDEF*/


typedef struct {
	char	transport[SCLEN];
	char	user[SCLEN];
	char	method[CLEN];
	char	maddr[CLEN];
	int	ttl;
	int	lr;
	int	rport;
	double	q;
	char	branch[CLEN];
	char	tag[CLEN];
	char	aux[CLEN];
}URIPARAM;


typedef struct sipurl_t{
	char	proto[CLEN];
	char	display[CLEN];
	char	username[CLEN];
	char	password[CLEN];
	char	host[CLEN];
	unsigned short int port;
	URIPARAM	param;
	char		tag[CLEN];
	char		aux[CLEN];
	struct sipurl_t	*next;
}URI;

typedef struct {
	int	type;
	int	message;
	char	method[SCLEN];
	URI	requri;	
	char	proto[SCLEN];
	int	ver;
	int	code;
	char	response[SCLEN];
}START;


typedef struct cseq_t{
	int	seq;
	char	method[SCLEN];
}CSEQ;

typedef struct via_t{
	char	proto[SCLEN];
	char	ver[SCLEN];
	char	trans[SCLEN];
	char	host[CLEN];
	unsigned short int port;
	URIPARAM	param;
	struct via_t 	*next;
}VIA;

typedef struct pauth_t{
	char	realm[SCLEN];
	char	domain[SCLEN];
	char	qop[SCLEN];
	char	opaque[SCLEN];
	char	nonce[SCLEN];
	char	cnonce[SCLEN];
	char	nc[SCLEN];
	char	uri[SCLEN];
	char	username[SCLEN];
	char	algorithm[SCLEN];
	char	stale[SCLEN];
	char	response[CLEN];
	char	aux[CLEN];
	char	passwd[SCLEN];
	char	method[SCLEN];

}PAUTH;
	

typedef struct general_t{
	char	body[CLEN];
	struct general_t *next;
} GENERAL;

typedef struct {
	CSEQ	cseq;
	int	expires;
	int	maxforwards;
	URI	from;
	URI	to;
	URI	*contact;
	URI	*route;
	URI	*recordroute;
	VIA	*via;
	int	contentLength;
	PAUTH	*authtc;
	PAUTH	*authrz;
	PAUTH	*wwwauthtc;
	PAUTH	*wwwauthrz;
	char	contentType[CLEN];
	char	callid[CLEN];
	char	userAgent[CLEN];
	GENERAL	*general;
}HEADER;

typedef	struct {
	START	start;
	HEADER	header;
	char	*contents;
	char	*buff;
	int	len;
	char	ip[SCLEN];
	int	port;
	char	to_ip[SCLEN];
	int	to_port;
}MESSAGE;



//------------------------------------------------------------
//Proto Type
void syserr(char *);
void  Response(int code,MESSAGE *);
int InitializeUDP(int);
int InitializeTLS(char *cacert,char *peerhost,int port);
void TerminateTLS(void);
void display_message(MESSAGE *);

//util.c
int SeparateLex(char *buff,char c,char **optr,int n);
char * SeparateLex1(char *buff,char c,char *optr,int *n);
char *SkipChars(char *ptr,char c);
void initialize_message_buffer(MESSAGE *mes);
void free_message_buffer(MESSAGE *mes);
int copy_message_buffer(MESSAGE *,MESSAGE *);
int  CalcHash(MESSAGE *,unsigned char *);
int CalcResponse(PAUTH *pauth);
//parser.c
int AnalyzePDU(char *rbuff,int rlen,MESSAGE *mes);
//header.c
int AnalyzeIntHeader(char *buff,int *val);
int AnalyzeCharHeader(char *buff,char *mes);
int AnalyzeURI(char *buff,URI *url );
int AnalyzeCSeq(char *buff,CSEQ *);
int AnalyzeVia(char *buff,VIA *via);
int AddVia(VIA **,unsigned char *);
int AddURI(URI **);
int SearchVia(VIA **,char *,int *);
int DeleteURI(URI **);
void DisplayURI(int level, URI *);
void DisplayPAUTH(PAUTH *);
int AnalyzePAUTH(char *buff,PAUTH *pauth);
//transfer
int Transfer(MESSAGE *mes);
//Hosts
void InitHosts(char *fname);
int SearchTransferAddress(MESSAGE *mes,char *ip, int *port,int *auth,char *passwd);
//
void logging(int,char *);
int MakeSendBuffer(MESSAGE *,char *);
int MakeURItoASC(URI *,char *,int);
//auth
int  GetAuthentication(MESSAGE *mes,char *passwd);
//process
void CheckProcess(void);
//Session
int CreateSession(MESSAGE *);
//SDP
int MakeSDP(char *uname,int port,char **sdp);
int AnalyzeSDP(char *sdp,int len ,char *,int *port);

extern  int debug;

extern void EncodeEscapeString(char *pinp,char *poutp);
extern	void Get_SelfData(char *,int *,char *,char *,int *);
extern void Get_ProxyData(char *,char *,char *,int *);
extern void Get_Ver(char *);
extern int SendRegister(int,PAUTH *,int tls);
extern int CheckRegister(void);
extern int RegisterResponse(MESSAGE *);
extern int GetAuthorizeHeaderBlock(MESSAGE *mes,PAUTH **pa);

extern void InitSession(void);
extern int  ProcessINVITE(MESSAGE *,char *,int *);
extern void *execute_receive_RTP(void *);
extern void *execute_send_RTP(void *);
extern int SendBYE(MESSAGE *);
extern short ulaw2linear(unsigned char	u_val);
extern unsigned char linear2ulaw(short	pcm_val);

