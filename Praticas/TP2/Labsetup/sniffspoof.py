from scapy.all import *

def spoof_pkt(pkt):
    # newSeq = 0
    # if ICMP in pkt:
    #     print("original packet.........")
    #     print ("Source IP : ", pkt[IP].src)
    #     print ("Destination IP : ", pkt[IP]. dst)
    #     srcIP = pkt[IP].dst
    #     dstIP = pkt[IP].src
    #     newIHL = pkt[IP].ihl
    #     newType = 0
    #     newId = pkt[ICMP].id
    #     newSeq = pkt[ICMP].seq
    #     data = pkt [Raw].load
    #     IPLayer = IP(src = srcIP, dst = dstIP, ihl = newIHL)
    #     ICMPLayer = ICMP(type = newType, id = newId, seq = newSeq)
    #     netPkt = IPLayer/ICMPLayer/data
    #     print("SRC: " + netPkt[IP].src)
    #     print("DST: " + netPkt[IP].dst)
    #     send(netPkt)

    if ICMP in pkt and pkt[ICMP].type == 8:
        a = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        a[IP].dst = pkt[IP].src
        b = ICMP(type=0,id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        newpacket = a/b/data
        send(newpacket)
    
# pkt = sniff(filter = "icmp and src host 10.0.2.6", prn = spoof_pkt)
pkt = sniff(filter="icmp", prn = spoof_pkt)