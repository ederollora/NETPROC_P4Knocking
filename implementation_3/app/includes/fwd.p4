
control Forward_to_Service(inout headers_t hdr,
                            inout metadata meta,
                              inout standard_metadata_t standard_metadata) {



    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table fwd_tb {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        default_action = drop;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            fwd_tb.apply();
        }
    }
}
