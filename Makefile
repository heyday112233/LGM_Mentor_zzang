CC=gcc

yijoo: send_arp.c
		$(CC) -o yijoo send_arp.c -lpcap -lnet

clean:

		rm -f yijoo
