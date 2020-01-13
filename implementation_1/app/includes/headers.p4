
#include "standard_h.p4"

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    icmp_t icmp;
    tcp_t tcp;
    udp_t udp;
}

struct pk_metadata_t {
    pk_stage_t stage;
    bit<32> index;
    bool direct_fwd;
    bool fwded;
    bool allowed;
}

struct metadata {
    pk_metadata_t pk_metadata;
}
