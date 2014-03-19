CC = gcc
CFLAGS = -ggdb -lpcap -o
HFILES = datalist.c
PARSEFILE = packetparse.c
OBJFILE = packetparse
INPUTFILE = smtp.pcap

all: $(HFILES) $(PARSEFILE)
	$(CC) $(CFLAGS) $(OBJFILE) $(HFILES) $(PARSEFILE)

parse: $(OBJFILE) $(INPUTFILE)
	./$(OBJFILE) -m $(INPUTFILE)

clean:
	rm $(OBJFILE)
	rm *.mail
