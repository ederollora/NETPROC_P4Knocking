
control Protected_Service(inout headers_t hdr,
                        inout metadata meta,
                              inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action not_allowed(){
        meta.pk_metadata.allowed = false;
        drop();
    }

    action allow_pkt(){
        meta.pk_metadata.allowed = true;
    }

    table protected_service_tb {
        key = {
            meta.pk_metadata.stage : exact;
            hdr.ipv4.dstAddr : lpm;
            hdr.ipv4.protocol : exact;
            hdr.tcp.dstPort : exact;
        }
        actions = {
            drop;
            allow_pkt;
            not_allowed;
            NoAction;
        }
        default_action = not_allowed;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            protected_service_tb.apply();
        }
    }
}
