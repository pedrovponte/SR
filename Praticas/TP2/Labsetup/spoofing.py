from scapy.all import *

a = IP()
a.dst = '10.0.2.3'
b = ICMP()
p = a/b
p.show()
send(p)