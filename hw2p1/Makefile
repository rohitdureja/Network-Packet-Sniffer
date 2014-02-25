CC=gcc
CFLAGS=-lpcap -o

all: packetparse.c
	$(CC) $(CFLAGS) packetparse packetparse.c

parse: packetparse
	./packetparse smtp.pcap > output.txt

clean:
	rm -f packetparse
	rm *.txt
