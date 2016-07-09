#define APP_NAME     "sniffex"
#define APP_DESC        "Sniffer example using libpcap"
#define APP_COPYRIGHT   "Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER  "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>


#define SNAP_LEN 1518


#define SIZE_ETHERNET 14



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


typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;            
    u_short th_dport;               
    tcp_seq th_seq;              
    tcp_seq th_ack;              
    u_char  th_offx2;             
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                
    u_short th_sum;           
    u_short th_urp;              
};





void PrintData(u_int startOctet, u_int endOctet, const u_char *data);
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_app_usage(void);


void
print_app_usage(void)
{

    printf("Usage: %s [interface]\n", APP_NAME);
    printf("\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
    printf("\n");

    return;
}


void PrintData(u_int startOctet, u_int endOctet, const u_char *data)
{
    for (u_int i = startOctet; i<=endOctet; i++)
    {
        printf("%.2x", data[i]);
    }
    printf("\n");


}




void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 1;                  
        

    const struct sniff_ethernet *ethernet;  
    const struct sniff_ip *ip;             
    const struct sniff_tcp *tcp;            

    int size_ip;
    int size_tcp;
    

    
    printf("\nPacket number %d:\n", count);
    count++;
        

    ethernet = (struct sniff_ethernet*)(packet);
        
    printf("Dst MAC: ");
    PrintData(0,5,ethernet->ether_dhost);
    
    printf("Src MAC: ");
    PrintData(0,5,ethernet->ether_shost);



    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

        
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));
        

    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }
        
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
        
    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    return;
}

int main(int argc, char **argv)
{

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];      
    pcap_t *handle;            
    struct bpf_program fp;      
    char filter_exp[]="";
    bpf_u_int32 mask;       
    bpf_u_int32 net;    
        int num_packets = -1;    

    dev = pcap_lookupdev(errbuf);
    
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }        

            
        printf("Device: %s\n", dev);

            
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }

            
        if (pcap_datalink(handle) != DLT_EN10MB) {
            fprintf(stderr, "%s is not an Ethernet\n", dev);
            exit(EXIT_FAILURE);
        }


        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n",
                    filter_exp, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

            
        pcap_loop(handle, num_packets, got_packet, NULL);

        pcap_freecode(&fp);
        pcap_close(handle);

        printf("\nCapture complete.\n");

        return 0;
}
