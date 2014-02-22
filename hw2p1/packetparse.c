#include<stdio.h>
#include"pcap.h"

int main(int argc, char *argv[])
{
	
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;	
	/*Set up device*/
	if(argc<2)
	{
		dev = pcap_lookupdev(errbuf);
		if(dev==NULL)
		{	
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		printf("Device: %s\n", dev);
	}
	else
	 {
		dev = argv[1];
		printf("Device: %s\n", dev);
	}
	/*Open device for sniffing*/
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle==NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	
	return 0;
}
