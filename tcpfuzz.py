#!/usr/bin/python

from optparse import OptionParser, OptionGroup
import random
from tcp_data import tcp_small_packets
from tcp_conn import tcp_one_syn
from tcp_option import tcp_one_option

if __name__ == "__main__":
	usage = "usage: ./tcpfuzz.py\n"
	usage += " basic option:\n"
	usage += "  --src [src] --dst [dst] --sport <sport> --dport [dport]\n"
	usage += " tcp connection fuzzing:\n"
	usage += "  --one-syn\n"
	usage += " tcp options fuzzing:\n"
	usage += " tcp data fuzzing:\n"
	usage += "  --small-packets\n"

	parser = OptionParser(usage)

	group = OptionGroup(parser,"basic options")
	group.add_option("", "--src", dest="src", help="source address")
	group.add_option("", "--dst", dest="dst", help="destination address")
	group.add_option("", "--sport", dest="sport", type="int", help="source port (optional)")
	group.add_option("", "--dport", dest="dport", type="int", help="destination port")
	parser.add_option_group(group)

	group = OptionGroup(parser,"tcp connection fuzzing")
	group.add_option("", "--one-syn", action="store_true", dest="one_syn", help="send one syn packet")
	parser.add_option_group(group)

	group = OptionGroup(parser,"tcp options fuzzing")
	group.add_option("", "--one-option", action="store_true", dest="one_option", help="fuzzing one tcp option with syn")
	parser.add_option_group(group)

	group = OptionGroup(parser,"tcp data fuzzing")
	group.add_option("", "--small-packets", action="store_true", dest="small_packets", help="send fast small packets")
	parser.add_option_group(group)

	(options, args) = parser.parse_args()

	if not options.src or not options.dst or not options.dport:
		parser.print_help()
		exit()

	if not options.sport:
		options.sport = random.randint(1024,65535)

	if options.one_syn:
		tcp_one_syn(options)

	if options.one_option:
		tcp_one_option(options)

	if options.small_packets:
		tcp_small_packets(options)
