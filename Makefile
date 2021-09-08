T=sipc

OBJ= auth.o buffer.o dump.o header.o log.o parser.o register.o resp.o sipc.o tls.o udp.o util.o


OPT=-Wall -ggdb

$(T):$(OBJ)
	gcc  -o $(T) $(LOPT) $(OBJ) -pthread -lm -lssl -lcrypto

.c.o:
	gcc  $(OPT) $(IOPT)  -c -o $*.o $<
$(OBJ):sip.h parser.h udp.h


auth_e.o:auth.c
	gcc $(OPT) -DEMULATION -o auth_e.o -ggdb -c auth.c
transfer_e.o:transfer.c
	gcc $(OPT) -DEMULATION  -o transfer_e.o -ggdb -c transfer.c
util:util.c
	gcc $(OPT) -o util -DMAIN util.c log.o md5.o -lssl -lcrypto 
parser:parser.c
	gcc $(OPT) -o parser -DTEST parser.c
htest:header.c util.o log.o
	gcc $(OPT) -o htest -DTEST header.c util.o log.o
url:url.c
	gcc $(OPT) -o url -DTEST url.c
dumpp:dump.c
	gcc $(OPT) -o dumpp -DTEST dump.c
tags: *.c
	ctags *.c
clean:
	rm -f *.o sipc
tar:	
	( cd ..; tar cvfz sipcnf/sipcnf.tgz sipcnf/*.c sipcnf/*.h  sipcnf/Makefile sipcnf/sipd.conf sipcnf/README.txt sipcnf/sd/* )

