#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define SIZE_ETHERNET 14
#define MAXBYTES2CAPTURE 2048 


struct sniff_ethernet {
   u_char  ether_dhost[ETHER_ADDR_LEN];   
   u_char  ether_shost[ETHER_ADDR_LEN];  
   u_short ether_type;                 
};


struct sniff_ip {
	u_char  ip_vhl;                
	u_char  ip_tos;               
	u_short ip_len;              
	u_short ip_id;               
	u_short ip_off;              
	 #define IP_RF 0x8000        
	 #define IP_DF 0x4000        
	 #define IP_MF 0x2000            
	 #define IP_OFFMASK 0x1fff    
	u_char  ip_ttl;              
	u_char  ip_p;                
	u_short ip_sum;                
	struct  in_addr ip_src,ip_dst; 
};


 #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
 #define IP_V(ip)                (((ip)->ip_vhl) >> 4)

void PrintData(u_int startOctet, u_int endOctet, const u_char *data);

void PrintData(u_int startOctet, u_int endOctet, const u_char *data)
{
    for (u_int i = startOctet; i<=endOctet; i++)
    {
        printf("%.2x", data[i]);
    }
    printf("\n");
}


    
int PCAP_NEXT(char argv[]){

	char *dev;
	int i=0; 
	bpf_u_int32 netaddr=0, mask=0;    
	struct bpf_program filter;       
	char errbuf[PCAP_ERRBUF_SIZE];    
	pcap_t *descr = NULL;             
	struct pcap_pkthdr *pkthdr;        
	struct sniff_ethernet *ethernet;  
	const u_char *packet=NULL; 
	const struct sniff_ip *ip;             
	const struct sniff_tcp *tcp;      
	int size_ip;      

	                   
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


	 if ( pcap_compile(descr, &filter, NULL, 1, mask) == -1){
	     fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
	     exit(1);
	 }


	 while(1){ 
	 	if ((pcap_next_ex(descr, &pkthdr, (const u_char **)&packet)) <= 0){  
	 		fprintf(stderr, "TIMEOUT.\n");
	 		continue;
	 	}

		ethernet = (struct sniff_ethernet*)(packet);
	    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

	    size_ip = IP_HL(ip)*4;
	    if (size_ip < 20) {
	        continue;
	    }

 
	   if (!strcmp(inet_ntoa(ip->ip_src),argv))
	   {
	   	 unsigned char buff[BUFSIZ];
	   	 unsigned char buff2[BUFSIZ];
	   	 FILE *fp;

	   	 	printf("       From: %s\n", inet_ntoa(ip->ip_src));

			fp = popen( "arp -n | grep `ip route | awk '/default/ {print $3}'` | awk '{print $3}'", "r");
   			if ( NULL == fp)
   			{
     		 perror( "popen() failed");
     			return -1;
   			}

	   		memset(buff, 0, sizeof(buff));
	   		memset(buff2, 0, sizeof(buff2));


	 		if((fgets( buff, BUFSIZ, fp)) == NULL ){
			fprintf(stderr, "get gateway failed\n");
			exit(EXIT_FAILURE);
	   		}

		    buff[strlen(buff)-1]='\0';
		    printf("get gateway: %s\n", buff);
		    pclose( fp);

	    sscanf(buff, "%02X:%02X:%02X:%02X:%02X:%02X", \
	    	(unsigned int *)&ethernet->ether_dhost[0], (unsigned int *)&ethernet->ether_dhost[1],\
	    	(unsigned int *)&ethernet->ether_dhost[2],(unsigned int *)&ethernet->ether_dhost[3],\
	    	(unsigned int *)&ethernet->ether_dhost[4],(unsigned int *)&ethernet->ether_dhost[5]);

		 		printf("Dst MAC: ");
		        PrintData(0,5,ethernet->ether_dhost);
		     
	   fp = popen( "ifconfig | awk '/eth0/ {print $5}'", "r");
	   if ( NULL == fp)
	   	{
	      perror( "popen() failed");
	     	return -1;
	   	}

	 if((fgets( buff2, BUFSIZ, fp)) == NULL ){
			fprintf(stderr, "get own failed\n");
			exit(EXIT_FAILURE);
	   }

	    buff2[strlen(buff2)-1]='\0';
	    printf("get own: %s\n", buff2);
	    pclose( fp);

		sscanf(buff2, "%02x:%02x:%02x:%02x:%02x:%02x", \
			(unsigned int *)&ethernet->ether_shost[0], (unsigned int *)&ethernet->ether_shost[1],\
			(unsigned int *)&ethernet->ether_shost[2],(unsigned int *)&ethernet->ether_shost[3],\
			(unsigned int *)&ethernet->ether_shost[4],(unsigned int *)&ethernet->ether_shost[5]); 
		        printf("Src MAC: ");
		        PrintData(0,5,ethernet->ether_shost);
		 
		        int result = pcap_inject(descr, packet, sizeof(packet));
		        if(result == -1){
		        	printf("FAIL\n");
		        	continue;
		        }
		        printf("==================================================================\n");
		} 

    }
    return 0;
}


int main(int argc, char *argv[]) {
	printf("%s", argv[1]);
	PCAP_NEXT(argv[1]);
}