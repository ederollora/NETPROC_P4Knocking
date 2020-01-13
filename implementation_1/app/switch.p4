#include <core.p4>
#include <v1model.p4>

#include "includes/defines.p4"
#include "includes/headers.p4"
#include "includes/parsers.p4"
#include "includes/checksum.p4"
#include "includes/incoming.p4"
#include "includes/protected.p4"
#include "includes/fwd.p4"
#include "includes/port_knocking.p4"
#include "includes/port_counters.p4"


control IngressImpl(inout headers_t hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata)
{
    Port_counters_ingress() port_counters_ingress;
    Incoming() inc;
    Protected_Service() pr;
    Port_Knocking() pk;
    Forward_to_Service() fwd;

    //if you try to allocate MAX_INDEX_INT (max unsigned integer value)
    // or MAX_INDEX_TEST (max signed integer value) it will crash.
    // Even with other lower values. Seems logical.
    // P4 switch s1 did not start correctly.
    // ../../utils/Makefile:35: recipe for target 'run' failed
    // make: *** [run] Error 1

    // Because this case is relatively unfefasible we consider only a little subnet
    // 10.0.0.0 - 10.7.7.255 of possible IPs and use them as index of our register.
    //TO use them as index we first subtract the IP to 
    register<pk_stage_t>(460798) port_knocking_stage_count;

    // size of index: as many as ip4Addr_t and size of register is pk_stage_t
    //register<bit<8>>(MAX_INDEX) port_knocking_stage_count;

    apply{

        port_counters_ingress.apply(hdr, standard_metadata);

        meta.pk_metadata.index = (bit<32>)hdr.ipv4.srcAddr - 167772160;
        port_knocking_stage_count.read(meta.pk_metadata.stage, (bit<32>)meta.pk_metadata.index);

        //This is used to know when to fwd a packet directly.
        // Like when it comes from a server, as a response of communication
        inc.apply(hdr, meta, standard_metadata);

        //If we dont fwd it then let's
        if(meta.pk_metadata.direct_fwd == false){
            pr.apply(hdr, meta, standard_metadata);
        }

        //If the packet is allowed or can be directly forwarded
        if(meta.pk_metadata.allowed == true || meta.pk_metadata.direct_fwd == true){
            fwd.apply(hdr, meta, standard_metadata);
        }

        //If packet is not allowed and is not directly forwarded
        if (meta.pk_metadata.direct_fwd == false && meta.pk_metadata.allowed == false){
            pk.apply(hdr, meta, standard_metadata);
        }

        //Finally store stage count in register
        port_knocking_stage_count.write((bit<32>)meta.pk_metadata.index, meta.pk_metadata.stage);

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
