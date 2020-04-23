#include "ipk-sniffer.h"

/* structs prototypes for gethostbyaddr() */
struct hostent* he;
struct in_addr addr, addr2;
struct sockaddr_in source, dest;

/* global variables */
char tempBuf[256], buf[1024];
static int count = 0;

/* struct which holds user params from commandline */
struct userArgs {
    char* interface;
    char* port;
    bool tcp;
    bool udp;
    int packetNumber;
    bool interfaceSet;
    bool portSet;
} userArgs;

/* initialization of struct */
int initStruct() {
    userArgs.interface = "";
    userArgs.tcp = false;
    userArgs.udp = false;
    userArgs.interfaceSet = false;
    userArgs.packetNumber = 1;
    userArgs.portSet = false;

    userArgs.port = (char*)malloc(8 * sizeof(char));
    if (userArgs.port == NULL) {
        fprintf(stderr, "Memory allocation wasn't successful\n");
        return 1;
    }
    return 0;
}

/* Function which parses arguments and stores parametres in userArgs struct */
int parseArgs(int argc, char** argv) {
    int opt;
    int port;
    char* endptr = NULL;

    while ((opt = getopt(argc, argv, ":i:p:tun:")) != -1) {
        switch (opt) {
        // interface option
        case 'i':
            userArgs.interface = optarg;
            userArgs.interfaceSet = true;
	    break;

        // port option
        case 'p':
            port = (int)strtol(optarg, &endptr, 10);
            if (*endptr) {
                fprintf(stderr, "Wrong port (-p) value!\n");
                return 1;
            }
	    if (port < 1024 || port > 65535) {
		fprintf(stderr, "Wrong port (-p) value!\n"\
		                "Must be in range 1024 <= port <= 65535\n");
		return 1;
	    }
            sprintf(userArgs.port, "port %d", port);
            userArgs.portSet = true;
            break;

        // if set, only tcp packets will be shown
        case 't':
            userArgs.tcp = true;
            break;

        // if set, only udp packets will be shown
        case 'u':
            userArgs.udp = true;
            break;

        // number of packets to be shown
        case 'n':
            userArgs.packetNumber = (int)strtol(optarg, &endptr, 10);
            if (*endptr) {
                fprintf(stderr, "Wrong number of packets (-n) value!\n");
                return 1;
            }

            if (userArgs.packetNumber <= 0) {
                fprintf(stderr, "Wrong number of packets (-n) value!\n");
                return 1;
            }
            break;

        default:
            fprintf(stderr, "Wrong parameter!\n");
            return 1;
        }
    }
    return 0;
}

/* Callback function for pcap_loop()
   Determines if packet is TCP or UDP and calls proper function
*/
void processPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer) {

    int size = header->len;
    struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
    case 6:  //TCP Protocol
        printTCP(buffer, size);
        break;

    case 17: //UDP Protocol
        printUDP(buffer, size);
        break;

    default:
        break;
    }
}


/* File name: sniffer.c
 * Author: Copyright (c) 2002 Tim Carstens
 * Date: 2002-01-07
 * Author's description: Demonstration of using libpcap
 * From website: tcpdump.org/sniffex.c
 *
 * My commentary: All rights reserved Tim Carstens
 *                I just borrowed this function for writing hex lines of packets to stdout
 *                Function was modfied a little for project purposes
 */

void print_hex_ascii_line(const u_char* payload, int len, int offset)
{
    int i;
    int gap;
    const u_char* ch;

    /* offset */
    printf("0x%04x   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }

    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }

    printf("   ");
    /* ascii (if printable) */
    ch = payload;

    for (i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");

    return;
}

/* File name: sniffer.c
 * Author: Copyright (c) 2002 Tim Carstens
 * Date: 2002-01-07
 * Author's description: Demonstration of using libpcap
 * From website: tcpdump.org/sniffex.c
 *
 * My commentary: All rights reserved Tim Carstens
 *                I just borrowed this function for writing formated lines of packets to stdout
 *                Function was modfied a little for project purposes by adding new parameter
                  and block of code which splits header of packet and payload with a new line
 */

void dataFlush(const u_char* payload, int len, int hdrlen) {
    bool flag = false;
    int len_rem = len;
    int line_width = 16;   /* number of bytes per line */
    int line_len;
    int offset = 0;     /* zero-based offset counter */
    const u_char* ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        
        /* splitting header from payload */
        if ((len_rem - (len - hdrlen)) < 16) {
            if (flag == false) {
                int temp = len_rem - (len - hdrlen);
                print_hex_ascii_line(ch, temp, offset);
                printf("\n");
                len_rem = len_rem - (len_rem - (len - hdrlen));
                ch = ch + temp;
                offset = offset + temp;
                flag = true;
                continue;
            }
        }
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);

        /* compute total remaining */
        len_rem = len_rem - line_len;

        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;

        /* add offset */
        offset = offset + line_width;

        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    printf("\n");

    return;
}

/* Function which get a timestamp and forms a header for our IPK project
 * Format: timestamp IP/HOSTNAME : SOURCE_PORT > IP/HOSTNAME : DEST_PORT
 */
void getTimestamp(const u_char* Buffer, int Size) {

    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    /* Getting timestamp and writing the header of packet*/
    struct timeval tv;
    time_t nowtime;
    struct tm* nowtm;

    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);

    strftime(tempBuf, sizeof(tempBuf), "%H:%M:%S", nowtm);          // time is written to tempBuf
    snprintf(buf, sizeof(buf), "%s.%06ld", tempBuf, tv.tv_usec);    // appending microseconds to tempBuf and storing it in buf

    /* Get host name, if it is not possible, ip will be written*/
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    source.sin_family = AF_INET;
    dest.sin_family = AF_INET;

    addr = source.sin_addr;
    addr2 = dest.sin_addr;

    snprintf(tempBuf, sizeof(tempBuf), "%s", buf);
    memset(buf, 0, sizeof(buf));

    if (he = (gethostbyaddr((const void*)&addr, sizeof(addr), AF_INET)))
        snprintf(buf, sizeof(buf), "%s %s :", tempBuf, he->h_name);
    else
        snprintf(buf, sizeof(buf), "%s %s :", tempBuf, inet_ntoa(source.sin_addr));

    he = 0;
    memset(tempBuf, 0, sizeof(tempBuf));

    if (he = (gethostbyaddr((const void*)&addr2, sizeof(addr2), AF_INET)))
        snprintf(tempBuf, sizeof(tempBuf), "%s :", he->h_name);
    else
        snprintf(tempBuf, sizeof(tempBuf), "%s :", inet_ntoa(dest.sin_addr));
}

/* Function which prints header of IPK project and TCP packet*/
void printTCP(const u_char* Buffer, int Size) {

    if (!userArgs.tcp && userArgs.udp) return;  // if udp only packets should be printed, return from func
    if (count == 0) return;                     // sometimes more packets were printed, so just a handler

    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    getTimestamp(Buffer, Size);
    char finalBuf[1024];

    snprintf(finalBuf, sizeof(finalBuf), "%s %u > %s %u", buf, ntohs(tcph->source), tempBuf, ntohs(tcph->dest));
    printf("%s\n\n", finalBuf);
    int hdrlen = iphdrlen + 14 + tcph->doff * 4;
    dataFlush(Buffer, Size, hdrlen);
    count--;
}

void printUDP(const u_char* Buffer, int Size) {

    if (userArgs.tcp && !userArgs.udp) return;
    if (count == 0) return;

    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct udphdr* udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    getTimestamp(Buffer, Size);
    char finalBuf[1024];

    snprintf(finalBuf, sizeof(finalBuf), "%s %u > %s %u", buf, ntohs(udph->source), tempBuf, ntohs(udph->dest));
    printf("%s\n\n", finalBuf);
    int hdrlen = iphdrlen + 14 + sizeof udph;
    dataFlush(Buffer, Size, hdrlen);
    count--;

}

/************************************ MAIN ************************************/
int main(int argc, char** argv) {

    int code = 0;
    if (code = initStruct()) return code;            // initialize struct for holding important data
    if (code = parseArgs(argc, argv)) return code;   // parses arguments
    count = userArgs.packetNumber;

    char error[PCAP_ERRBUF_SIZE];       // buffer for error messages
    pcap_if_t* interfaces, * temp;
    struct bpf_program fp;
    bpf_u_int32 mask;		            // netmask of our sniffing device
    bpf_u_int32 net;
    int countOfInterface = 0, i = 0;

    // finds all interfaces on system
    if (pcap_findalldevs(&interfaces, error) == -1)
    {
        printf("Error in pcap_findalldevs\n");
        return EXIT_FAILURE;
    }

    /*  - loop through founded interfaces, if interface is matched with user
          defined interface, breaks the loop and continue in code
        - if any interface match with user defined interface, error is raised
        - if user doesn't specify interface, all of system interfaces are written to
          stdout and program ends with EXIT_SUCCESS
    */
    for (temp = interfaces; temp; temp = temp->next) {
        if (userArgs.interfaceSet) {
            if (strcmp(userArgs.interface, temp->name) == 0) {
                countOfInterface++;
                break;
            }

            if (countOfInterface == 0) {
                fprintf(stderr, "No valid interface was found!\n");
                return EXIT_FAILURE;
            }
        }
        else {
            printf("%d. %s", ++i, temp->name);
            if (temp->description)
                printf(" (%s)\n", temp->description);
            else
                printf(" (No description available)\n");

            if ((temp->next == NULL) && (countOfInterface == 0))
                return 0;
        }
    }
    /* File name: sniffer.c
     * Author: Copyright (c) 2002 Tim Carstens
     * Date: 2002-01-07
     * Author's description: Demonstration of using libpcap
     * From website: tcpdump.org/sniffex.c
     *
     * My commentary: All rights reserved Tim Carstens
     *                Following fragment of code was borrowed from https://www.tcpdump.org/pcap.html ,
     *                but it's property of Tim Carstens
     *                Code was modified just a little for project purposes
     */

    // for network mask, so we can apply a filter later on
    if (pcap_lookupnet(userArgs.interface, &net, &mask, error) == -1) {
        fprintf(stderr, "Netmask wasn't found or enable to reach for device %s\n", userArgs.interface);
        net = 0;
        mask = 0;
    }

    // opening specified device for sniffing
    pcap_t* dev = pcap_open_live(userArgs.interface, BUFSIZ, 1, 0, error);
    if (!dev) {
        fprintf(stderr, "Opening of device %s wasn't successful. Error: %s \n", userArgs.interface, error);
        return EXIT_FAILURE;
    }

    // applying a filter
    if (pcap_compile(dev, &fp, userArgs.port, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", userArgs.port, pcap_geterr(dev));
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(dev, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", userArgs.port, pcap_geterr(dev));
        return EXIT_FAILURE;
    }

    pcap_freecode(&fp);     // pcap_compile() may have memory leak, so we have to free it

    // loop with a callback function
    pcap_loop(dev, userArgs.packetNumber, processPacket, NULL);
    pcap_close(dev);
    free(userArgs.port);
    return EXIT_SUCCESS;
}
