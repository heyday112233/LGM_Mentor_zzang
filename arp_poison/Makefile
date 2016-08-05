CC=gcc

all: yijoo yijoo2

yijoo: send_arp.c
	$(CC) -g -o yijoo send_arp.c -lpcap -lnet

yijoo2: 1relay_arp.c
	$(CC) -g -o yijoo2 1relay_arp.c -lpcap

clean:
	rm -f yijoo*
