#include <stdio.h>


void print_mac_address(u_int8_t *address){
    fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x\n",
    address[0], address[1], address[2],
    address[3], address[4], address[5]);
}