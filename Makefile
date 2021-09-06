T=sipc

PLAIN_OBJ=sipc.o util.o udp.o log.o parser.o header.o dump.o resp.o buffer.o invite.o session.o sdp.o register.o auth.o rtp.o g711.o fft.o recpt.o play.o dtmf.o tls.o


OBJ=$(PLAIN_OBJ)

OPT=-Wall -ggdb

$(T):$(OBJ)
	gcc  -o $(T) $(LOPT) $(OBJ) -pthread -lm -lssl -lcrypto


test:$(EMU_OBJ)
	gcc $(OPT) -o siptest $(LOPT) $(EMU_OBJ)

.c.o:
	gcc  $(OPT) $(IOPT)  -c -o $*.o $<
$(OBJ):sip.h parser.h udp.h

sipc_e.o:sipc.c
	gcc $(OPT) -DEMULATION -o sipc_e.o -ggdb -c sipc.c

auth_e.o:auth.c
	gcc $(OPT) -DEMULATION -o auth_e.o -ggdb -c auth.c

sipc_p.o:sipc.c
	gcc $(OPT) -DPROXY  -o sipc_p.o -ggdb -c sipc.c

sipc_pe.o:sipc.c
	gcc $(OPT) -DPROXY  -DEMULATION -o sipc_pe.o -ggdb -c sipc.c

transfer_p.o:transfer.c
	gcc $(OPT) -DPROXY  -o transfer_p.o -ggdb -c transfer.c

transfer_e.o:transfer.c
	gcc $(OPT) -DEMULATION  -o transfer_e.o -ggdb -c transfer.c
util:util.c
	gcc $(OPT) -o util -DMAIN util.c log.o md5.o -lssl -lcrypto 
cli:udp.c
	gcc $(OPT) -o cli -DTEST udp.c
parser:parser.c
	gcc $(OPT) -o parser -DTEST parser.c
htest:header.c util.o log.o
	gcc $(OPT) -o htest -DTEST header.c util.o log.o
url:url.c
	gcc $(OPT) -o url -DTEST url.c
dumpp:dump.c
	gcc $(OPT) -o dumpp -DTEST dump.c
notify:notify.c
	gcc $(OPT) -o notify -DTEST notify.c udp.o
db:db.c
	gcc $(OPT) -g -o db -DTEST db.c 
tags: *.c
	ctags *.c
clean:
	rm -f *.o sipc
tar:	
	( cd ..; tar cvfz sipcnf/sipcnf.tgz sipcnf/*.c sipcnf/*.h  sipcnf/Makefile sipcnf/sipd.conf sipcnf/README.txt sipcnf/sd/* )

