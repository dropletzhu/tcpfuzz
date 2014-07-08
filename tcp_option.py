#!/usr/bin/python

from scapy.all import *
import random

tcp_options = {
#type,length,value,description
	'0':['1','',"End of option list"],
	'1':['1','',"No operation"],
	'2':['4','1460',"MSS"],
	'3':['3','9',"Window scale factor"],
	'4':['2','',"SACK permitted"],
	'5':['n','',"SACK"],
	'6':['6','',"Echo"],
	'7':['6','',"Echo reply"],
	'8':['10','',"Timestamp"],
	'9':['2','',"Partial order connection permitted"],
	'10':['3','',"Partial order service profile"],
	'11':['6','',"Connection count"],
	'12':['6','',"CC new"],
	'13':['6','',"CC echo"],
	'14':['3','',"Alternate checksum request"],
	'15':['n','',"Alternate checksum data"],
	'16':['n','',"Skeeter"],
	'17':['n','',"Bubba"],
	'18':['3','',"Trailer checksum option"],
	'19':['18','',"MD5 signature"],
	'20':['n','',"SCPS capabilities"],
	'21':['n','',"Selective negative acknowledgements"],
	'22':['n','',"Record boundaries"],
	'23':['n','',"Corruption experienced"],
	'24':['n','',"SNAP"],
	'26':['n','',"TCP compression filter"],
	'27':['8','',"Quick start filter"],
	'28':['4','',"User timeout"],
	'29':['n','',"TCP-AO"],
	'30':['n','',"MPTCP"],
	'38':['n','',"WX 38"],
	'39':['n','',"WX 39"],
	'253':['n','',"RFC3692 experiment 1"],
	'254':['n','',"RFC3692 experiment 2"],
}

def __tcp_build_one_option(type):
	if type < 0 or type > 255:
		print "tcp option type is wrong: %d" % type
		return None
	
	type_str = str(type)
	if not tcp_options.has_key(type_str):
		return None

	list = tcp_options[type_str]

	if list[0] == 'n':
		length = random.randint(2,40)
	else:
		length = int(list[0])

	if list[1] == '' and length > 2:
		value = '8' * (length - 2)
	else:
		value = list[1]

	option = ""

	if length == 1:
		option = "%c" % type
	else:
		option = "%c%c%s" % (type,length,value)

	pad = length % 4
	if pad != 0:
		option = option + '1'*(4-pad)

	return option

def tcp_one_option(options):
	init_seq = 0

	ip = IP(src=options.src, dst=options.dst)
	i = 0
	for i in range(0,255):
		option = __tcp_build_one_option(i)
		if option != None:
			syn = TCP(sport=random.randint(1024,65535), dport=options.dport, flags="S", seq=init_seq)
			syn.dataofs = 5 + len(option)/4
			packet = (ip/syn/option)
			send(packet)

if __name__ == "__main__":
	__tcp_build_one_option(0)
	__tcp_build_one_option(3)
	__tcp_build_one_option(300)
	i = 0
	for i in range(0,255):
		__tcp_build_one_option(i)
