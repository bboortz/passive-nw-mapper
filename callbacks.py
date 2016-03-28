from scapy.all import *

class Callbacks(object):

	def __init__(self):
		self.cb_recv_pkt = self.recv_pkt


	def recv_pkt(self, pkt):
		if Ether in pkt:
			return pkt.sprintf(r"%Ether.src% -%ARP.psrc%")
		if ARP in pkt:
			return self.recv_pkt_arp(pkt)
		if IP in pkt and TCP in pkt:
			return self.recv_pkt_tcp(pkt)

		elif IP in pkt and UDP in pkt:
			return self.recv_pkt_udp(pkt)

		elif IP in pkt and ICMP in pkt:
			return self.recv_pkt_icmp(pkt)

		else:
			return pkt.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}")
			# pkt.show()


	def recv_pkt_arp(self, pkt):
		if pkt[ARP].op == 1: #who-has (request)
			return "ARP-Request: " + pkt[ARP].psrc + " is asking about " + pkt[ARP].pdst
		if pkt[ARP].op == 2: #is-at (response)
			return "ARP-Response: " + pkt[ARP].hwsrc + " has address " + pkt[ARP].psrc

	def recv_pkt_tcp(self, pkt):
		return pkt.sprintf("IP/TCP {IP:%IP.src% -> %IP.dst%\n}{TCP: %TCP.sport% -> %TCP.dport%\n}")

	def recv_pkt_udp(self, pkt):
		return pkt.sprintf("IP/UDP {IP:%IP.src% -> %IP.dst%\n}{UDP: %UDP.sport% -> %UDP.dport%\n}")

	def recv_pkt_icmp(self, pkt):
		return pkt.sprintf("IP/ICMP {IP:%IP.src% -> %IP.dst%\n}{ICMP: %ICMP.type% / %ICMP.code%\n}")


