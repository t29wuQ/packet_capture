#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "packet_capture.h"

void usage(char *prog){
    fprintf(stderr, "Usage: %s <device>\n", prog);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]){
    pcap_t *handle;
    const unsigned char *packet;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    struct bpf_program fp;
    bpf_u_int32 net;

    if ((dev = argv[1]) == NULL)
        usage(argv[0]);

    if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    int count = 0;
    while(1){
        if((packet = pcap_next(handle, &header)) == NULL)
            continue;
        fprintf(stdout, "%d:\n", count);
        analyze_ethernet(packet);
        fprintf(stdout, "\n\n");
        count++;
    }
}