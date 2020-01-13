
control Incoming(inout headers_t hdr,
                                inout metadata meta,
                                      inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action not_from_server() {
        meta.pk_metadata.direct_fwd = false;
    }

    action direct_forward() {
        meta.pk_metadata.direct_fwd = true;
    }

    table port_tb {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            direct_forward;
            not_from_server;
            drop;
            NoAction;
        }
        default_action = not_from_server;
    }

    apply {
        port_tb.apply();
    }
}
