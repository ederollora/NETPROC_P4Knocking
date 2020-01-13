#include <core.p4>
#include <v1model.p4>

#include "includes/defines.p4"
#include "includes/headers.p4"
#include "includes/parsers.p4"
#include "includes/checksum.p4"
#include "includes/incoming.p4"
#include "includes/firewall.p4"
#include "includes/forward.p4"
#include "includes/portknocking_packetin.p4"
#include "includes/port_counters.p4"


control IngressImpl(inout headers_t hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata)
{
    Port_counters_ingress() port_counters_ingress;
    Incoming() inc;
    Firewall() firewall;
    Forward_to_Service() forward;
    PortKnocking_PacketIn() pk_packet_in;

    apply{

        port_counters_ingress.apply(hdr, standard_metadata);

        // Check if it can be directly forwarded

        inc.apply(hdr, meta, standard_metadata);

        if(meta.pk_metadata.direct_fwd == false){
            firewall.apply(hdr, meta, standard_metadata);
        }

        // If it can be forwarded for one reason or another
        if(meta.pk_metadata.allowed == true || meta.pk_metadata.direct_fwd == true){
            forward.apply(hdr, meta, standard_metadata);
        }else{
            // If the src IP has no ID assigned
            if(hdr.tcp.isValid() && hdr.tcp.ctrl == SYN){
                pk_packet_in.apply(hdr, meta, standard_metadata);
            }
        }
    }
}

control EgressImpl(inout headers_t hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata)
{
    Port_counters_egress() port_counters_egress;

    apply{
        port_counters_egress.apply(hdr, standard_metadata);
    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
