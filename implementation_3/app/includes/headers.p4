
#include "standard_h.p4"

struct headers_t {
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    icmp_t icmp;
    tcp_t tcp;
    udp_t udp;
}

struct pk_metadata_t {
    pk_stage_t stage;
    bit<16> id;
    bool direct_fwd;
    bool allowed;
    bool has_id;
    bool protected_port;
}

struct metadata {
    pk_metadata_t pk_metadata;
}
