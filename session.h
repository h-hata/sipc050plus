#define SESSION_MAX     100
#define VOID_ST         0
#define RECPT_ST	1
#define ACTIVE_ST       2
#define TIMEOUT_ST      3
#define KILLED_ST       4
#define GUARD_TIME      PROCESS_TIME_OUT
#define	SIP_INVITED	1
#define	SIP_WAIT_ACK	2
#define	SIP_TALK	3
#define	REC_LOOP	2
#define	REC_ONE		1	
#define	INCOMMING	1
#define	OUTGOING	2

typedef struct process_t {
        int     status;
	int	sip_st;
        MESSAGE *invite;
        int     cnf;
        int     direction;
        time_t  lifetime;
        time_t  update;
        int	rtpaddr;
        int     rtpport;
	int	bufflock;
        int     buffsize;
	unsigned int	sqc;
	unsigned int	timing;
	FILE	*fp;
	int		rec_count;
        unsigned char   buff[512];
}SESSION_TABLE;

extern SESSION_TABLE   session[SESSION_MAX];
extern int DeleteSession(MESSAGE *);
extern int RegisterSession(MESSAGE *invite,int cnf,int direction,int rtpaddr,int rtpport);extern int EnterSession(SESSION_TABLE *ses,int room);
