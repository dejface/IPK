#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <stdbool.h>
#include <getopt.h>
#include <pcap.h>
#include <time.h>
#include <ctype.h>
#include <netinet/ip6.h>

void processPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer);
int parseArgs(int argc, char** argv);
int initStruct();
void getTimestamp(const u_char* Buffer, int Size);
void printTCP(const u_char* Buffer, int Size);
void printUDP(const u_char* Buffer, int Size);
void dataFlush(const u_char* payload, int len, int hdrlen);
void print_hex_ascii_line(const u_char* payload, int len, int offset);
