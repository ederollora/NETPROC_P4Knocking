
// packet in
@controller_header("packet_in")
header packet_in_header_t {
    bit<9>  ingress_port;
    bit<7>  _padding;
}

// packet out
@controller_header("packet_out")
header packet_out_header_t {
    bit<9>  egress_port;
    bit<7>  _padding;
}


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    // Diffserv -> DSCP + ECN
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t{
    bit<8> tp;
    bit<8> code;
    bit<16> chk;
    bit<16> id;
    bit<16> seqNum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset; // how long the TCP header is
    bit<3>  res;
    bit<3>  ecn; //Explicit congestion notification
    bit<6>  ctrl; // URG,ACK,PSH,RST,SYN,FIN
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}
