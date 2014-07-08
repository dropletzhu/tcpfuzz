#!/usr/bin/python

from scapy.all import *

def tcp_one_syn(options):
    init_seq = 0

    ip = IP(src=options.src, dst=options.dst)
    syn = TCP(sport=options.sport, dport=options.dport, flags="S", seq=init_seq)
    send(ip/syn)

if __name__ == "__main__":
	print "unit test\n"
