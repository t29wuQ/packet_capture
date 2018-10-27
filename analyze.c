#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include "packet_capture.h"


void analyze_ip_v4(const unsigned char *packet_pointer){
    struct ip *header;
    header = (struct ip *)packet_pointer;

    fprintf(stdout, "Distination IP Address: ");
    fprintf(stdout, "%s\n", inet_ntoa(header->ip_dst));
    fprintf(stdout, "Source IP Address: ");
    fprintf(stdout, "%s\n", inet_ntoa(header->ip_src));

}

void analyze_ethernet(const unsigned char *packet_pointer){
    struct ether_header *header;
    header = (struct ether_header *)packet_pointer;
    
    fprintf(stdout, "Distination Mac Address: ");
    print_mac_address(header->ether_dhost);
    fprintf(stdout, "Source Mac Address: ");
    print_mac_address(header->ether_shost);
    
    switch (ntohs(header->ether_type)){
        case 0x0800: //IPv4
            analyze_ip_v4((unsigned char *)(packet_pointer + sizeof(struct ether_header)));
            break;
        case 0x0806: //ARP
            break;
    }
}

