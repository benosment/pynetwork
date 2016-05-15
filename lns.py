#! /usr/bin/env python2
# lns.py - local network scan
# must run as sudo

from scapy.all import srp
from scapy.all import Ether
from scapy.all import ARP
import socket

answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)
print('%-30s %-30s %-30s' % ('hostname', 'ip address', 'mac address'))
print('-' * 80)
for answer in answered:
    #import pdb; pdb.set_trace()
    try:
        hostname = socket.gethostbyaddr(answer[1].psrc)[0]
    except:
        hostname = '-'
    print('%-30s %-30s %-30s' % (hostname, answer[1].psrc, answer[1].src))
