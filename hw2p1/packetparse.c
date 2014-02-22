#include<stdio.h>
#include"pcap.h"


void packet_handler(u_char* user, const struct pcap_pkthdr *pkt_header, const u_char * pkt_data){
	int i;
	printf("P:");
	for(i=1;i<(pkt_header->caplen+1);i++){
	    printf("%.2x",pkt_data[i-1]);
		printf(" ");
	}
	printf("\n\n");
}


int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;	

	handle = pcap_open_offline("sampleimf.pcap",errbuf);
	
	if(handle==NULL){
	    fprintf(stderr,"%s",errbuf);
	}
	
	pcap_loop(handle,0,packet_handler,NULL);
	
	
	return 0;
}
