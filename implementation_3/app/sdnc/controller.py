#!/usr/bin/env python2.7
import argparse
import grpc
import os
import sys
import json
import yaml
from modules.Id_Manager import IdManager

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '/home/p4/projects/P4knocking_NETPROC/utils'))

import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

from scapy.all import Packet
from scapy.all import BitField
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether


class Packet_In(Packet):
    name = "Packet_In"

    fields_desc = [
        BitField('port', 0, 9)
    ]


def load_switches_conf():
    data = {}
    with open('./config/switches.json', 'r') as json_file:
        #data = json.load(json_file)
        data = yaml.safe_load(json_file)

    return data


def load_pr_rules():
    rules = {}
    with open('./config/pr_rules.json', 'r') as json_file:
        #rules = json.load(json_file)
        rules = yaml.safe_load(json_file)
    return rules


def load_sdnc_pkt_in_rules():
    rules = {}
    with open('./config/port_knock_in_rules.json', 'r') as json_file:
        #rules = json.load(json_file)
        rules = yaml.safe_load(json_file)

    return rules


def load_fwd_rules():
    rules = {}
    with open('./config/fwd_rules.json', 'r') as json_file:
        #rules = json.load(json_file)
        rules = yaml.safe_load(json_file)

    return rules


def load_pk_rules():
    rules = {}
    with open('./config/portknocking_rules.json', 'r') as json_file:
        #rules = json.load(json_file)
        rules = yaml.safe_load(json_file)

    return rules


def connect_to_switches(switches_config):
    switches = []
    for switch in switches_config:
        switches.append(
            p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=switch["name"],
                address=switch["address"],
                device_id=switch["device_id"],
                proto_dump_file=switch["proto_dump_file"]))

    return switches


def send_master_arbitration_updates(switches):
    for switch in switches:
        switch.MasterArbitrationUpdate()


def set_pipelines(switches, p4info_helper, bmv2_file_path):
    for switch in switches:
        switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_file_path)


def install_direct_forwarding_rules(p4info_helper, switches):
    ports = {
        "ports":  [
            [1, 2],
            [1],
            []
        ]
    }

    for idx, switch in enumerate(switches):
        for port in ports["ports"][idx]:
            table_entry = p4info_helper.buildTableEntry(
                table_name="IngressImpl.inc.port_tb",
                match_fields={
                    "standard_metadata.ingress_port": port
                },
                action_name="IngressImpl.inc.direct_forward",
                action_params={}
            )

            switch.WriteTableEntry(table_entry)


def install_rules_protected_services(p4info_helper, switches, switches_conf, rules):
    for idx, switch in enumerate(switches):

        sw = switches_conf[idx]["name"]
        rules_l = rules[sw]["rules"]
        actions_l = rules[sw]["actions"]

        for index, rule in enumerate(rules_l):
            table_entry = p4info_helper.buildTableEntry(
                table_name="IngressImpl.pr.protected_service_tb",
                match_fields={
                    "meta.pk_metadata.stage": rule["stage"],
                    "hdr.ipv4.dstAddr": (rule["ipDstAddr"], 32),
                    "hdr.tcp.dstPort": rule["tcpDstPort"]
                },
                action_name=actions_l[index]["name"],
                action_params={}
            )

            switch.WriteTableEntry(table_entry)


def install_port_knock_in_rules(p4info_helper, switches, switches_conf, rules):
    for idx, switch in enumerate(switches):

        sw = switches_conf[idx]["name"]
        rules_l = rules[sw]["rules"]
        actions_l = rules[sw]["actions"]

        for index, rule in enumerate(rules_l):
            table_entry = p4info_helper.buildTableEntry(
                table_name="IngressImpl.pk_in.portknocking_in_tb",
                match_fields={
                    "hdr.ipv4.dstAddr": (rule["ipDstAddr"], 32),
                    "hdr.tcp.dstPort": rule["tcpDstPort"],
                    "hdr.tcp.ctrl": rule["tcpCtrl"]
                },
                action_name=actions_l[index]["name"],
                action_params={}
            )

            switch.WriteTableEntry(table_entry)


def install_forwarding_rules(p4info_helper, switches, switches_conf, rules):
    for idx, switch in enumerate(switches):

        sw = switches_conf[idx]["name"]
        rules_l = rules[sw]["rules"]
        actions_l = rules[sw]["actions"]

        for index, rule in enumerate(rules_l):
            table_entry = p4info_helper.buildTableEntry(
                table_name="IngressImpl.fwd.fwd_tb",
                match_fields={
                    "hdr.ipv4.dstAddr": (rule["ipDstAddr"], 32)
                },
                action_name=actions_l[index]["name"],
                action_params={
                    "dstAddr": actions_l[index]["values"]["dstAddr"],
                    "port": actions_l[index]["values"]["port"]
                }
            )

            switch.WriteTableEntry(table_entry)


def install_pip2id_rules(p4info_helper, switch, src_ip, new_id):
    table_entry = p4info_helper.buildTableEntry(
        table_name="IngressImpl.i2i.ip_2_id_tb",
        match_fields={
            "hdr.ipv4.srcAddr": (src_ip, 32)
        },
        action_name="IngressImpl.i2i.id_found",
        action_params={
            "current_id": new_id
        }
    )

    switch.WriteTableEntry(table_entry)


def install_pk_rules(p4info_helper, switches, switches_conf, rules):
    for idx, switch in enumerate(switches):
        sw = switches_conf[idx]["name"]
        rules_l = rules[sw]["rules"]
        actions_l = rules[sw]["actions"]

        for index, rule in enumerate(rules_l):
            table_entry = p4info_helper.buildTableEntry(
                table_name="IngressImpl.pk.port_knocking_tb",
                match_fields={
                    "meta.pk_metadata.stage": rule["stage"],
                    "hdr.ipv4.dstAddr": (rule["ipDstAddr"], 32),
                    "hdr.tcp.dstPort": rule["tcpDstPort"]
                },
                action_name=actions_l[index]["name"],
                action_params={}
            )

            switch.WriteTableEntry(table_entry)


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file

    ip2id_l = {}
    id_manager = IdManager(2 ** 16 - 1)

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    switches_conf = load_switches_conf()
    pr_rules = load_pr_rules()
    sdnc_pi_rules = load_sdnc_pkt_in_rules()
    fwd_rules = load_fwd_rules()
    pk_rules = load_pk_rules()

    try:

        switches = connect_to_switches(switches_conf["switches"])

        send_master_arbitration_updates(switches)

        set_pipelines(switches, p4info_helper, bmv2_file_path)

        install_direct_forwarding_rules(p4info_helper, switches)

        install_rules_protected_services(p4info_helper, switches, switches_conf["switches"], pr_rules["switches"])

        install_port_knock_in_rules(p4info_helper, switches, switches_conf["switches"], sdnc_pi_rules["switches"])

        install_forwarding_rules(p4info_helper, switches, switches_conf["switches"], fwd_rules["switches"])

        switch_2 = switches[1]
        while True:
            packet_in = switch_2.PacketIn()
            print("Recibido paquete: "+str(packet_in))
            if packet_in.WhichOneof('update') == 'packet':
                pkt = Ether(_pkt=packet_in.packet.payload)

                src_ip = pkt.getlayer(IP).src
                print("SRC IP: " + str(src_ip))

                new_id = id_manager.get_id()
                print("New ID: " + str(new_id))
                ip2id_l[str(src_ip)] = new_id

                install_pip2id_rules(p4info_helper, switch_2, src_ip, new_id)
                install_pk_rules(p4info_helper, switches, switches_conf["switches"], pk_rules["switches"])


    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='../build/switch.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='../build/switch.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)

    main(args.p4info, args.bmv2_json)
