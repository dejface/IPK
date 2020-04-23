CC=gcc
CFLAGS= -std=gnu99

all: ipk-sniffer

ipk-sniffer.o: ipk-sniffer.c ipk-sniffer.h
        $(CC) $(CFLAGS) -c ipk-sniffer.c -o $@

ipk-sniffer: ipk-sniffer.o
        $(CC) $(CFLAGS) ipk-sniffer.o -o $@ -lpcap
