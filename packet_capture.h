void analyze_ethernet(const unsigned char *packet_pointer);
void print_mac_address(u_int8_t *address);
struct tcp{
    u_int16_t sport;
    u_int16_t dport;
    u_int32_t snumber;
    u_int32_t anumber;
    u_int16_t flag;
    u_int16_t wsize;
    u_int16_t sum;
    u_int16_t pointer;
};