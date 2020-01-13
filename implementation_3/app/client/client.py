from scapy.all import *
from time import sleep
import random

conf.verb=0

def knock(ports):
    print "[*] Knocking on ports"+str(ports)
    for dport in range(0, len(ports)):
        ip = IP(dst = "10.0.2.2")
        SYN = ip/TCP(dport=ports[dport], flags="S", window=14600, options=[('MSS',1460)])
        send(SYN)
        sleep(3)

ports = [22,10000,20000,30000]
knock(ports)

print("Knocked")
