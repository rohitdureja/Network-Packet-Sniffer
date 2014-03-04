#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "datalist.h"

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	#define IP_RF 0x8000            /* reserved fragment flag */
	#define IP_DF 0x4000            /* dont fragment flag */
	#define IP_MF 0x2000            /* more fragments flag */
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
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
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
    u_short uh_sport;               /* source port */
    u_short uh_dport;               /* destination port */
    u_short uh_ulen;                /* datagram length */
    u_short uh_sum;                 /* checksum */
};

int tcp_count = 0;
int udp_count = 0;
int other_count = 0;

struct connection_list *list = NULL;

/** utilitiy function which prints MAC address in proper format **/
void printMACAddr(const u_char* host) 
{
    int i = 0;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        if (i < ETHER_ADDR_LEN-1) {
            printf("%02x.", host[i]);
        }
            else printf("%02x", host[i]);
    }
}


int tcp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum;
    size_t length=len;
 
    // Calculate the sum                                            //
    sum = 0;
    while (len > 1)
    {
            sum += *buf++;
            if (sum & 0x80000000)
                sum = (sum & 0xFFFF) + (sum >> 16);
            len -= 2;
    }
    if ( len & 1 )
    // Add the padding if the packet lenght is odd          //
        sum += *((uint8_t *)buf);
        // Add the pseudo-header                                        //
    sum += *(ip_src++);
    sum += *ip_src;
    sum += *(ip_dst++);
    sum += *ip_dst;
    sum += htons(IPPROTO_TCP);
    sum += htons(length);
    // Add the carries                                              //
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
            // Return the one's complement of sum                           //
    return ( (uint16_t)(~sum)  );
}
 
void packet_handler_hw2p1(u_char* user, const struct pcap_pkthdr *pkt_header, const u_char *packet){
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
    const struct sniff_udp *udp;
	const char *payload;

	int size_ip;
	int size_tcp;
	int size_payload;

    // length of text used for checksum
    int size_csum;
    // computed TCP Checksum used for verification
    int tcp_csum;
    // tells us whether packet is TCP (1), UDP (2), other (0)
    int tcpUdp = 0;
	// ethernet header
	ethernet = (struct sniff_ethernet*)(packet);
    
    // not an IP packet
    if (ethernet->ether_type != 8) {
        printf("other ");
        printMACAddr(ethernet->ether_shost);
        printMACAddr(ethernet->ether_dhost);
        printf("\n");
        return;
    }

	// ip header
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
    
    // figures out type of protocol
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("TCP ");
            tcpUdp = 1;
            tcp_count ++;
            break;
        case IPPROTO_UDP:
            printf("UDP ");
            tcpUdp = 2;
            udp_count++;
            break;
        default:
            printf("other ");
            other_count++;
            break;
    }

    // print ethernet addresses
    printMACAddr(ethernet->ether_shost);
    printf(" ");
    printMACAddr(ethernet->ether_dhost);
    printf(" ");

    printf("%s ", inet_ntoa(ip->ip_src));
    printf("%s ", inet_ntoa(ip->ip_dst));


    // TCP info
    if (tcpUdp == 1) {
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        printf("%d ", size_payload);
        printf("%d ", ntohs(tcp->th_sport));
        printf("%d ", ntohs(tcp->th_dport));
        printf("0x%04x ", ntohs(tcp->th_sum));
        size_csum = ntohs(ip->ip_len) - size_ip;
        tcp_csum = tcp_checksum(tcp, size_csum, inet_addr(inet_ntoa(ip->ip_src)),inet_addr(inet_ntoa(ip->ip_dst)));
        if(tcp_csum)
            printf("N");
        else
            printf("Y");

    }

    // UDP info
    else if (tcpUdp == 2) {
        udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
        // UDP Header is 8 bytes
        size_payload = ntohs(ip->ip_len) - (size_ip + 8);
        printf("%d ", size_payload);
        printf("%d ", ntohs(udp->uh_sport));
        printf("%d ", ntohs(udp->uh_dport));
    }

    // Other info
    else{
        size_payload = ntohs(ip->ip_len) - size_ip;
        printf("%d ", size_payload);
    }
    printf("\n");
}

void packet_handler_hw2p2(u_char* user, const struct pcap_pkthdr *pkt_header, const u_char *packet) {
    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const struct sniff_udp *udp;
    const char *payload;

    struct packet_data packet_data;


    int size_ip;
    int size_tcp;
    unsigned long size_payload;

    // length of text used for checksum
    int size_csum;
    // computed TCP Checksum used for verification
    int tcp_csum;
    // tells us whether packet is TCP (1), UDP (2), other (0)
    int tcpUdp = 0;
    // ethernet header
    ethernet = (struct sniff_ethernet*)(packet);
    
    // not an IP packet
    if (ethernet->ether_type != 8) {
        return;
    }

    // ip header
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    
    // figures out type of protocol
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            tcpUdp = 1;
            tcp_count ++;
            break;
        case IPPROTO_UDP:
            tcpUdp = 2;
            udp_count++;
            break;
        default:
            other_count++;
            break;
    }



    // TCP info
    if (tcpUdp == 1) {
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        size_csum = ntohs(ip->ip_len) - size_ip;
        tcp_csum = tcp_checksum(tcp, size_csum, inet_addr(inet_ntoa(ip->ip_src)),inet_addr(inet_ntoa(ip->ip_dst)));
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        if(!tcp_csum) {
            packet_data.th_sport = tcp->th_sport;
            packet_data.th_dport = tcp->th_dport;
            packet_data.th_flags = tcp->th_flags;
            packet_data.payload_size = size_payload;
            packet_data.th_flags = tcp->th_flags;
            packet_data.ip_src = ip->ip_src;
            packet_data.ip_dst = ip->ip_dst;

            add_packet_to_connection_list(&list, packet_data);
			print_payload_content(&list, packet_data,payload);
        }
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;	
    if (argc < 2) {
        printf("Need to specify filename!\n");
        exit(1);
    }
    if (argc == 2) {
        if(!strcmp(argv[1],"-t")) {
            printf("Need to specify filename!\n");
            exit(1);
        }
        else
        {
            handle = pcap_open_offline(argv[1],errbuf);
            if(handle==NULL) {
                fprintf(stderr,"%s",errbuf);
            }
            else {
                pcap_loop(handle,0,packet_handler_hw2p1,NULL);
                printf("%d %d %d %d\r\n",tcp_count+udp_count+other_count,tcp_count,udp_count,other_count);
            }
        }
    }
    if (argc>2) {
        if(!strcmp(argv[1], "-t")) {
            handle = pcap_open_offline(argv[2],errbuf);
            if(handle==NULL) {
                fprintf(stderr,"%s",errbuf);
            }
            else {
                pcap_loop(handle,0,packet_handler_hw2p2,NULL);
                print_connection_list(&list);
                /* write files here */
            }
        }
    }

    return 0;
}
