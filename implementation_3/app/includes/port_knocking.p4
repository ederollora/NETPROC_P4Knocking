
control Port_Knocking(inout headers_t hdr,
                        inout metadata meta,
                              inout standard_metadata_t standard_metadata) {


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action reset_stage(){
        meta.pk_metadata.stage = 0;
    }

    action modify_stage(){
        meta.pk_metadata.stage = meta.pk_metadata.stage + 1;
    }


    table port_knocking_tb {
        key = {
            meta.pk_metadata.stage : exact;
            hdr.ipv4.dstAddr : lpm;
            hdr.tcp.dstPort : exact;
        }
        actions = {
            modify_stage;
            reset_stage;
            NoAction;
        }
        default_action = reset_stage;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            port_knocking_tb.apply();
        }
    }
}
