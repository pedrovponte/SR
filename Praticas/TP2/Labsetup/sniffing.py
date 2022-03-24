#!/usr/bin/env python3

from scapy.all import *

a = IP()
a.show()

def print_pkt(pkt):
    pkt.show()
    
# pkt_icmp = sniff(iface='br-05f629fdd555', filter='icmp', prn=print_pkt)

# pkt_tcp = sniff(iface='br-05f629fdd555', filter='tcp and dst host 23 and src host 10.9.0.5', prn=print_pkt)

pkt_subnet = sniff(iface='br-05f629fdd555', filter='net 8.8.8.0/24', prn=print_pkt)

