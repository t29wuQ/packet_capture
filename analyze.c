#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "packet_capture.h"

void analyze_ethernet(const unsigned char *packet_pointer){
    struct ether_header *header;
    header = (struct ether_header *)packet_pointer;
    
    fprintf(stdout, "Distination Mac Address: ");
    print_mac_address(header->ether_dhost);
    fprintf(stdout, "Source Mac Address: ");
    print_mac_address(header->ether_shost);
    
    switch (ntohs(header->ether_type)){
        case 0x0800: //IPv4
            break;
        case 0x0806: //ARP
            break;
    }
}

