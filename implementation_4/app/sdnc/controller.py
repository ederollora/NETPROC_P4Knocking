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
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


class Packet_In(Packet):
    name = "Packet_In"

    fields_desc = [
        BitField('port', 0, 9)
    ]


class PortKnocking:
    def __init__(self, *args, **kwargs):
        self.load()
        self.knock_stage = {}
        pass

    def load(self):
        rules = {}
        with open('config/knocks.json', 'r') as json_file:
            # rules = json.load(json_file)
            rules = yaml.safe_load(json_file)

        self.config = rules

    def check(self, src_ip, dst_ip, port):

        if dst_ip not in self.config["knocks"]:
            return

        if src_ip not in self.knock_stage:
            self.knock_stage[src_ip] = {}
        if dst_ip not in self.knock_stage[src_ip]:
            self.knock_stage[src_ip][dst_ip] = 0

        sequence = self.config["knocks"][dst_ip]
        stage = self.knock_stage[src_ip][dst_ip]

        print("Before port check: ("+src_ip+" - "+dst_ip+" - "+str(port)+"): "+str(self.knock_stage[src_ip][dst_ip]))

        if port == sequence[stage]:
            self.knock_stage[src_ip][dst_ip] += 1
        else:
            self.knock_stage[src_ip][dst_ip] = 0

        print("After port check: ("+src_ip+" - "+dst_ip+" - "+str(port)+"): "+str(self.knock_stage[src_ip][dst_ip]))


    def has_authed(self, src_ip, dst_ip):

        if dst_ip not in self.config["knocks"]:
            return False

        if src_ip not in self.knock_stage or \
                dst_ip not in self.knock_stage[src_ip]:
            return False

        sequence = self.config["knocks"][dst_ip]
        stage = self.knock_stage[src_ip][dst_ip]

        if stage == len(sequence):
            return True

        return False


def load_switches_conf():
    data = {}
    with open('./config/switches.json', 'r') as json_file:
        #data = json.load(json_file)
        data = yaml.safe_load(json_file)

    return data


def load_firewall_rules():
    rules = {}
    with open('config/firewall_rules.json', 'r') as json_file:
        rules = yaml.safe_load(json_file)
    return rules


def load_forward_rules():
    rules = {}
    with open('config/forwarding_rules.json', 'r') as json_file:
        #rules = json.load(json_file)
        rules = yaml.safe_load(json_file)

    return rules


def load_pk_packet_in_rules():
    rules = {}
    with open('config/pk_packet_in_rules.json', 'r') as json_file:
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


def install_firewall_rules(p4info_helper, switches, switches_conf, rules):
    for idx, switch in enumerate(switches):

        sw = switches_conf[idx]["name"]
        rules_l = rules[sw]["rules"]
        actions_l = rules[sw]["actions"]

        for index, rule in enumerate(rules_l):
            table_entry = p4info_helper.buildTableEntry(
                table_name="IngressImpl.firewall.firewall_tb",
                match_fields={
                    "hdr.ipv4.srcAddr": (rule["ipSrcAddr"]["address"], rule["ipSrcAddr"]["mask"]),
                    "hdr.ipv4.dstAddr": rule["ipDstAddr"],
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
                table_name="IngressImpl.pk_packet_in.portknocking_in_tb",
                match_fields={
                    "hdr.ipv4.dstAddr": (rule["ipDstAddr"]["address"], rule["ipDstAddr"]["mask"]),
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
                table_name="IngressImpl.forward.fwd_tb",
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


def install_allowance_rules(p4info_helper, switch, src_ip, dst_ip, ports):

    for port in ports:
        table_entry = p4info_helper.buildTableEntry(
            table_name="IngressImpl.firewall.firewall_tb",
            match_fields={
                "hdr.ipv4.srcAddr": (src_ip, 32),
                "hdr.ipv4.dstAddr": dst_ip,
                "hdr.tcp.dstPort": port
            },
            action_name="IngressImpl.firewall.allow_pkt",
            action_params={}
        )

        switch.WriteTableEntry(table_entry)


def main(p4info_file_path, bmv2_file_path):

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    pk = PortKnocking()
    pk.load()

    switches_conf = load_switches_conf()
    firewall_rules = load_firewall_rules()
    forward_rules = load_forward_rules()
    pk_packet_in_rules = load_pk_packet_in_rules()

    try:

        switches = connect_to_switches(switches_conf["switches"])

        send_master_arbitration_updates(switches)

        set_pipelines(switches, p4info_helper, bmv2_file_path)

        install_direct_forwarding_rules(p4info_helper, switches)

        install_firewall_rules(p4info_helper, switches, switches_conf["switches"], firewall_rules["switches"])

        install_port_knock_in_rules(p4info_helper, switches, switches_conf["switches"], pk_packet_in_rules["switches"])

        install_forwarding_rules(p4info_helper, switches, switches_conf["switches"], forward_rules["switches"])

        switch_2 = switches[1]
        while True:
            packet_in = switch_2.PacketIn()
            print("Recibido paquete: "+str(packet_in))
            if packet_in.WhichOneof('update') == 'packet':
                pkt = Ether(_pkt=packet_in.packet.payload)

                src_ip = pkt.getlayer(IP).src
                dst_ip = pkt.getlayer(IP).dst
                tcp_dPort = pkt.getlayer(TCP).dport
                print("SRC IP: " + str(src_ip))
                print("DST IP: " + str(dst_ip))
                print("TCP DPORT: " + str(tcp_dPort))

                if pkt.getlayer(TCP):
                    pk.check(src_ip, dst_ip, tcp_dPort)

                if pk.has_authed(src_ip, dst_ip):
                    install_allowance_rules(p4info_helper, switch_2, src_ip, dst_ip, pk.config["hidden_services"][dst_ip])


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
