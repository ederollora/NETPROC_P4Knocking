#include <core.p4>
#include <v1model.p4>

#include "includes/defines.p4"
#include "includes/headers.p4"
#include "includes/parsers.p4"
#include "includes/checksum.p4"
#include "includes/incoming.p4"
#include "includes/ip_2_id.p4"
#include "includes/protected.p4"
#include "includes/fwd.p4"
#include "includes/port_knocking.p4"
#include "includes/portknocking_packetin.p4"
#include "includes/port_counters.p4"


control IngressImpl(inout headers_t hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata)
{
    Port_counters_ingress() port_counters_ingress;
    Incoming() inc;
    Ip_2_Id() i2i;
    Protected_Service() pr;
    Forward_to_Service() fwd;
    PortKnocking_PacketIn() pk_in;
    Port_Knocking() pk;


    register<pk_stage_t>(BIT16_INDEX) pk_reg;

    apply{

        port_counters_ingress.apply(hdr, standard_metadata);

        // Check if it can be directly forwarded

        inc.apply(hdr, meta, standard_metadata);

        if (meta.pk_metadata.direct_fwd == false){
            i2i.apply(hdr, meta, standard_metadata);
        }

        if(meta.pk_metadata.has_id == true){
            pk_reg.read(meta.pk_metadata.stage, (bit<32>)meta.pk_metadata.id);
            pr.apply(hdr, meta, standard_metadata);
        }else{
            meta.pk_metadata.allowed = false;
        }

        // If it can be forwarded for one reason or another
        if(meta.pk_metadata.allowed == true || meta.pk_metadata.direct_fwd == true){
            fwd.apply(hdr, meta, standard_metadata);
        }else{
            // If the src IP has no ID assigned
            if(meta.pk_metadata.has_id == false){
                pk_in.apply(hdr, meta, standard_metadata);
            }else{
                if(hdr.tcp.ctrl == SYN){
                    //Finally this might be a knock indeed
                    pk.apply(hdr, meta, standard_metadata);
                    pk_reg.write((bit<32>)meta.pk_metadata.id, meta.pk_metadata.stage);
                }
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
