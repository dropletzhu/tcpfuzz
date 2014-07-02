#!/usr/bin/python

from optparse import OptionParser
from scapy.all import *

def tcp_fast_reset(options):
	init_seq = 100

	ip = IP(src=options.src, dst=options.dst)
	syn = TCP(sport=options.sport, dport=options.dport, flags="S", seq=init_seq)
	syn_ack = sr1(ip/syn)
	print syn_ack.window

	ack_seq = syn_ack.seq + 1
	ack = TCP(sport=options.sport, dport=options.dport, flags="A", seq=init_seq+1, ack=ack_seq)
	send(ip/ack)

	time.sleep(5)

	seq = init_seq + 1
	payload = '0' * 128
	i = 0
	while i < 8:
		while seq < (i+1)*65535:
			ack = TCP(sport=options.sport, dport=options.dport, flags="A", seq=seq, ack=ack_seq)
			send(ip/ack/payload)
			seq += 128
		i += 1
		time.sleep(1)

	i = 1
	while i < 8:
		j = 0
		seq = 8*65535 + 128
		while j < 65535:
			rst = TCP(sport=options.sport, dport=options.dport, flags="R", seq=seq, ack=ack_seq)
			send(ip/rst)
			j += 1
		i += 1
		time.sleep(1)


if __name__ == "__main__":
	usage = "usage: ./tcpfuzz.py -s [src] -d [dst] -q [sport] -p [dport]\n"

	parser = OptionParser(usage)
	parser.add_option("-s", "--src", dest="src", help="source address")
	parser.add_option("-d", "--dst", dest="dst", help="destination address")
	parser.add_option("-q", "--sport", dest="sport", type="int", help="source port")
	parser.add_option("-p", "--dport", dest="dport", type="int", help="destination port")
	(options, args) = parser.parse_args()

	if not options.dst or not options.dport:
		parser.print_help()
		exit()

	tcp_fast_reset(options)
