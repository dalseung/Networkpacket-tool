import dpkt, pcap
import socket
import re
icmp_type = {0:'Echo Reply', 3:'Destination Network Unreachable', 5:'Redirect', 8:'Echo Request',11:'TTL expired in trans'}
protocols = {1:'ICMP',6:'TCP',7:'ECHO',17:'UDP',20:'FTP',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',68:'DHCP',69:'TFTP',80:'HTTP',110:'POP3',143:'IMAP4',161:'SNMP',443:'HTTPS',520:'RIP'}


def mac_addr(address):
	return ':'.join('%02x' % dpkt.compat.compat_ord(b) for b in address) #%02x : 앞의 빈자리를 0으로 채우기


def inet_to_str(inet):
	try:
		return socket.inet_ntop(socket.AF_INET, inet)
	except ValueError:
		return socket.inet_ntop(socket.AF_INET6, inet)


def ether(p):
	eth = dpkt.ethernet.Ethernet(p)
	print('<Ethernet Frame>')
	print('Source MAC Address:', mac_addr(eth.src))
	print('Destination MAC Address:', mac_addr(eth.dst))
	print('Ether Type:', hex(eth.type))
	print("\n")
	try:
		if(eth.type == 0x800):
			IPv4(eth.data)
		elif(eth.type == 0x86DD):
			IPv6(eth.data)
		elif(eth.type == 0x806):
			ARP(eth.data)
		else:
			print("지원하지 않는 프로토콜입니다.")
	except:	 
		pass


def IPv4(ip):
	print('<IPv4 Frame>')
	print('Version:', ip.v)
	print('Length:', ip.hl)
	print('Type of Service:', ip.tos)
	print('Total Length:', ip.len)
	print('Identification:', hex(ip.id), '(', ip.id, ')')
	print('Flags:', ip.rf, ip.df, ip.mf)
	print('Fragment Offest:', ip.offset)
	print('Time to Live:', ip.ttl)
	ip_protocol = ip.p
	print('Protocol:', ip_protocol, '(', protocols[ip_protocol], ')')
	print('Header Checksum:', hex(ip.sum))
	print('Source IP Address:', inet_to_str(ip.src))
	print('Destination IP Address:', inet_to_str(ip.dst))
	if ip.opts != "":
		print('Options:', ip.opts)
	print("\n")
	if(ip.p == 6):
		TCP(ip.data)
	elif(ip.p == 17):
		UDP(ip.data)


def IPv6(ip):
	print('<IPv6 Frame>')
	print('Version:', ip.v)
	print('Traffic class:', hex(ip.fc))
	print('Flow label:', hex(ip.flow))
	print('Payload length:', ip.plen)
	print('Next header:', ip.nxt)
	print('Hop limit:', ip.hlim)
	print('Source IP Address:', inet_to_str(ip.src))
	print('Destination IP Address:', inet_to_str(ip.dst))
	print("\n")
	if(nxt == 6):
		TCP(ip.data)
	elif(nxt == 17):
		UDP(ip.data)


op_list = ["tmp", "request", "reply"]
def ARP(arp):
	print('<ARP Frame>')
	print('Hardware Type: Ethernet  (%d)' %arp.hrd)
	print('Protocol Type:', hex(arp.pro))
	print('Hardware size:', arp.hln)
	print('Protocol size:', arp.pln)
	print('Opcode: ' + op_list[arp.op] + " (" + str(arp.op) + ")")
	print('Sender MAC Address:', mac_addr(arp.sha))
	print('Sender IP Address:', inet_to_str(arp.spa))
	print('Target MAC Address:', mac_addr(arp.tha))
	print('Target IP Address:', inet_to_str(arp.tpa))
	print("\n")


def UDP(udp):
	print("<UDP Frame>")
	print('Source port:', udp.sport)
	print('Destination port:', udp.dport)
	print('Length:', udp.ulen)
	print('Chceksum:', udp.sum)
	print('\n')


def TCP(tcp):
	print("<TCP Frame>")
	print('Source port:', tcp.sport)
	print('Destination port:', tcp.dport)
	print('Sequence Number:', tcp.seq)
	print('Acknowledgment Number:', tcp.ack)
	print('Offset:', tcp.off)
	print('Flags:', tcp.flags)
	print('Window size:', tcp.win)
	print('Checksum:', tcp.sum)
	print('Urgent pointer:', tcp.urp)
	print('Option and Padding:', tcp.opts)
	print('\n')
	if(tcp.dport == 80):
		request=dpkt.http.Request(tcp.data)
		HTTP_request(request)
	if(tcp.sport == 80):
		response=dpkt.http.Response(tcp.data)
		HTTP_response(response)


def ICMP(icmp):
	print('<ICMP Frame>')
	print('Type:' + str(icmp.type) + '(' + icmp_type[icmp.type] + ')')
	print('Code:' + str(icmp.code))
	print('Checksum:' + str(hex(icmp.sum)))
	icmpdata = ICMP_Data(repr(icmp.data))


def ICMP_Data(icmpdata):
	icmpdatalst = re.split("[\'(, ]", icmpdata)
	if (icmpdatalst[0] == 'Echo'):
		print('Identifier:' + icmpdatalst[1][3:])
		print('Sequence Number:' + icmpdatalst[3][4:])
		print('Data:' + icmpdatalst[6])
		print('Data length:' + str(len(icmpdatalst[6])))
		print()
		print()
	else:
		print(icmpdatalst)
		print()
		print()


def HTTP_request(http):
	print('<HTTP Request Frame>')
	print(http)

def HTTP_response(http):
	print('<HTTP Response Frame>')
	print(http)
