CC = gcc
CFLAGS = -lpcap -o
HFILES = datalist.c
PARSEFILE = packetparse.c
OBJFILE = packetparse
INPUTFILE = smtp.pcap

all: $(HFILES) $(PARSEFILE)
	$(CC) $(CFLAGS) $(OBJFILE) $(HFILES) $(PARSEFILE)

parse: $(OBJFILE) $(INPUTFILE)
	./$(OBJFILE) -t $(INPUTFILE)

clean:
	rm $(OBJFILE)
	rm *.meta
