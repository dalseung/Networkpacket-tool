import dpkt, pcap
import socket

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
	print('Flags:', ip.rf, ip.df, ip.mf) #와이어샤크에서는 꺽쇠로 모여있음
	print('Fragment Offest:', ip.offset)
	print('Time to Live:', ip.ttl)
	print('Protocol:', ip.p)
	print('Header Checksum:', hex(ip.sum))
	print('Source IP Address:', inet_to_str(ip.src))
	print('Destination IP Address:', inet_to_str(ip.dst))
	if ip.opts == "":
		print('Options:', ip.opts)
	print("\n")


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
