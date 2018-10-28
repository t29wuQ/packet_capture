#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include "packet_capture.h"

void analyze_tcp(const unsigned char *packet_pointer){
    struct tcp *header;
    header = (struct tcp *)packet_pointer;
    fprintf(stdout, "Source Port: ");
    fprintf(stdout, "%d\n", ntohs(header->sport));
    fprintf(stdout, "Distination IP Address: ");
    fprintf(stdout, "%d\n",  ntohs(header->dport));
    fprintf(stdout, "SequenceNumber: %d\n", ntohs(header->snumber));
    fprintf(stdout, "AcknowledgmentNumber: %d\n", ntohs(header->anumber));
    u_int16_t flag = ntohs(header->flag);
    fprintf(stdout, "URG: %d ACK: %d PSH: %d RST: %d SYN: %d FIN: %d\n",
    (flag & 32) >> 5, (flag & 16) >> 4, (flag & 8) >> 3,
    (flag & 4) >> 2, (flag & 2) >> 1, flag & 1);
}

void analyze_ip_v4(const unsigned char *packet_pointer){
    struct ip *header;
    header = (struct ip *)packet_pointer;

    fprintf(stdout, "Source IP Address: ");
    fprintf(stdout, "%s\n", inet_ntoa(header->ip_src));
    fprintf(stdout, "Distination IP Address: ");
    fprintf(stdout, "%s\n", inet_ntoa(header->ip_dst));

    unsigned char *next_pointer = (unsigned char *)(packet_pointer + sizeof(struct ip));
    switch(header->ip_p){
        case 6: //TCP
            analyze_tcp(next_pointer);
            break;
    }

}

void analyze_ethernet(const unsigned char *packet_pointer){
    struct ether_header *header;
    header = (struct ether_header *)packet_pointer;
    
    fprintf(stdout, "Distination Mac Address: ");
    print_mac_address(header->ether_dhost);
    fprintf(stdout, "Source Mac Address: ");
    print_mac_address(header->ether_shost);
    
    unsigned char *next_pointer = (unsigned char *)(packet_pointer + sizeof(struct ether_header));
    switch (ntohs(header->ether_type)){
        case 0x0800: //IPv4
            analyze_ip_v4(next_pointer);
            break;
        case 0x0806: //ARP
            break;
    }
}

