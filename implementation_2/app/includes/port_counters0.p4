
control Port_counters_ingress(inout headers_t hdr,
                              inout standard_metadata_t standard_metadata) {

    counter(MAX_PORTS, CounterType.packets) ingress_port_counter;

    apply {
        ingress_port_counter.count((bit<32>) standard_metadata.ingress_port);
    }
}

control Port_counters_egress(inout headers_t hdr,
                             inout standard_metadata_t standard_metadata) {

    counter(MAX_PORTS, CounterType.packets) egress_port_counter;

    apply {
        egress_port_counter.count((bit<32>) standard_metadata.egress_port);
    }
}
