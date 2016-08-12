#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MAXBUF 0xFFFF
#define MAXURL 4096
#define MAX 1024
#define PACKET_SIZE 65536


/*
* Pre-fabricated packets.
*/
typedef struct
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;

char data[MAX][MAX];
int uIndex;

/*
* Prototypes
*/
static void PacketInit(PPACKET packet);
void urllist_init();
int checkUrl(char *packet);
void log(char* url);

int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	UINT8 packet[MAXBUF];
	UINT packet_len;
	UINT size_ip, size_tcp;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PVOID payload;
	UINT payload_len;
	PACKET reset0;
	PPACKET reset = &reset0;
	unsigned i;
	INT16 priority = 404;       // Arbitrary.

	urllist_init();
	PacketInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;

	// Open the Divert device:
	handle = WinDivertOpen(
		"outbound && "              // Outbound traffic only
		"ip && "                    // Only IPv4 supported
		"tcp.DstPort == 80 && "     // HTTP (port 80) only
		"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, priority, 0
	);
	if (handle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("OPENED WinDivert\n");

	// Main loop:
	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		ip_header = (PWINDIVERT_IPHDR *)packet;
		size_ip = (ip_header->HdrLength) * 4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}

		tcp_header = (PWINDIVERT_TCPHDR *)(packet + size_ip);
		size_tcp = (tcp_header->HdrLength) * 4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}

		payload = (PVOID *)(packet + (size_ip + size_tcp));
		payload_len = ntohs(ip_header->Length) - (size_ip + size_tcp);
		checkUrl(payload);
		WinDivertSend(handle, packet, packet_len, &addr, NULL);

		
	}
}

/*
* Initialize a PACKET.
*/
static void PacketInit(PPACKET packet)
{
	memset(packet, 0, sizeof(PACKET));
	packet->ip.Version = 4;
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->ip.Length = htons(sizeof(PACKET));
	packet->ip.TTL = 64;
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

void urllist_init() {
	FILE *fp;
	int i = 0;
	char* tmp;
	int buf_size = MAX*MAX;

	fp = fopen("mal_site.txt", "r");
	tmp = malloc(buf_size);
	uIndex = 0;

	while (fgets(data[uIndex], buf_size, fp)) {
		uIndex++;
	}

	for (i = 0; i < uIndex; i++) {
		printf("%s \n", data[i]);
	}
	fclose(fp);
}
int checkUrl(char *packet) {
	char *ptr;
	char copy[PACKET_SIZE];
	char *cUrl;
	int i;

	ptr = NULL;
	cUrl = NULL;
	memset(copy, "\0", BUFSIZ);

	strcpy(copy, packet);
	ptr = strstr(copy, "Host: ");
	ptr = strtok(ptr, "\n");
	cUrl = ptr + strlen("Host: ");
	printf("URL: %s\n", cUrl);

	for (i = 0; i<uIndex; i++) {
		if (strstr(cUrl, data[i]) != NULL) {
			printf("blocked: %s\n", cUrl);
			log(cUrl);
			return 1;
		}
	}
	return 0;
}

void log(char* url) {

	FILE *fp;

	fp = fopen("result.txt", "a");

	fprintf(fp, "%s is blocked\n", url);

	fclose(fp);



}