
control PortKnocking_PacketIn(inout headers_t hdr,
                          inout metadata meta,
                              inout standard_metadata_t standard_metadata) {

    action send_to_cpu(){
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        meta.pk_metadata.protected_port = true;
    }

    table portknocking_in_tb {
        key = {
            hdr.ipv4.dstAddr : lpm;
            hdr.tcp.dstPort : exact;
            hdr.tcp.ctrl : exact;
        }
        actions = {
            send_to_cpu;
            NoAction;
        }
        default_action = NoAction;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            portknocking_in_tb.apply();
        }
    }
}
