
control Ip_2_Id(inout headers_t hdr,
                        inout metadata meta,
                              inout standard_metadata_t standard_metadata) {


    // ******************************************************************** //

    action no_id(){
        meta.pk_metadata.has_id = false;
    }

    action id_found(id_t current_id){
        meta.pk_metadata.id = current_id;
        meta.pk_metadata.has_id = true;
    }

    // Table to get an ID from a source IP address

    table ip_2_id_tb {
        key = {
            hdr.ipv4.srcAddr : lpm;
        }
        actions = {
            id_found;
            no_id;
        }
        default_action = no_id;
    }

    apply {
        if(hdr.ipv4.isValid()){
            ip_2_id_tb.apply();
        }
    }
}
