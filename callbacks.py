from scapy.all import *
from pymongo import MongoClient
import time
import json

class Callbacks(object):

	def __init__(self):
		self.cb_recv_pkt = self.upload_pkt
		self.client =  MongoClient("mongodb://localhost:27017")
		self.db = self.client.chameleon4
		self.coll_layer4 = self.db.layer4_packets
		self.coll_layer3 = self.db.layer3_packets
		self.coll_layer2 = self.db.layer2_packets


	def upload_pkt(self, pkt):
		pkt_json = self.recv_pkt(pkt)

		if TCP in pkt  or  UDP in pkt:
			self.coll_layer4.insert_one(pkt_json)

		elif IP in pkt  or  IPv6 in pkt:
			self.coll_layer3.insert_one(pkt_json)

		elif Ether in pkt  or  ARP in pkt:
			self.coll_layer2.insert_one(pkt_json)

		print( "insert: %s" % pkt_json )



	def recv_pkt(self, pkt):
		pkt_parsed = {}
		pkt_parsed["timestamp"] = int(time.time())

		if ARP in pkt:
			self.recv_pkt_arp(pkt, pkt_parsed)

		if Ether in pkt:
			self.recv_pkt_ether(pkt, pkt_parsed)

		if LLC in pkt:
			self.recv_pkt_llc(pkt, pkt_parsed)

		if IP in pkt:
			self.recv_pkt_ip(pkt, pkt_parsed)

		elif IPv6 in pkt:
			self.recv_pkt_ipv6(pkt, pkt_parsed)

		if ICMP in pkt:
			self.recv_pkt_icmp(pkt, pkt_parsed)

		elif UDP in pkt:
			self.recv_pkt_udp(pkt, pkt_parsed)

		elif TCP in pkt:
			self.recv_pkt_tcp(pkt, pkt_parsed)

		if len(pkt_parsed.keys()) > 1:
			pkt_json = json.dumps(pkt_parsed)
#			return pkt_json
			return pkt_parsed
		else:
			print pkt.show()


	def recv_pkt_arp(self, pkt, pkt_parsed):
		if pkt[ARP].op == 1: #who-has (request)
			pkt_parsed["arp"] = {}
			pkt_parsed["arp"]["operation"] = "request"
			pkt_parsed["arp"]["psrc"] = pkt.sprintf(r"%ARP.psrc%")
			pkt_parsed["arp"]["pdst"] = pkt.sprintf(r"%ARP.pdst%")
		if pkt[ARP].op == 2: #is-at (response)
			pkt_parsed["arp"] = {}
			pkt_parsed["arp"]["operation"] = "response"
			pkt_parsed["arp"]["hwsrc"] = pkt.sprintf(r"%ARP.hwsrc%")
			pkt_parsed["arp"]["psrc"] = pkt.sprintf(r"%ARP.psrc%")


	def recv_pkt_llc(self, pkt, pkt_parsed):
		pkt_parsed["llc"] = {}
		pkt_parsed["llc"]["ctrl"] = pkt.sprintf(r"%LLC.ctrl%")


	def recv_pkt_ether(self, pkt, pkt_parsed):
		if Ether in pkt:
			pkt_parsed["ether"] = {}
			pkt_parsed["ether"]["src"] = pkt.sprintf(r"%Ether.src%")
			pkt_parsed["ether"]["dst"] = pkt.sprintf(r"%Ether.dst%")


	def recv_pkt_ip(self, pkt, pkt_parsed):
		pkt_parsed["ip"] = {}
		pkt_parsed["ip"]["src"] = pkt.sprintf(r"%IP.src%")
		pkt_parsed["ip"]["dst"] = pkt.sprintf(r"%IP.dst%")


	def recv_pkt_ipv6(self, pkt, pkt_parsed):
		pkt_parsed["ipv6"] = {}
		pkt_parsed["ipv6"]["src"] = pkt.sprintf(r"%IPv6.src%")
		pkt_parsed["ipv6"]["dst"] = pkt.sprintf(r"%IPv6.dst%")


	def recv_pkt_tcp(self, pkt, pkt_parsed):
		pkt_parsed["tcp"] = {}
		pkt_parsed["tcp"]["sport"] = pkt.sprintf(r"%TCP.sport%")
		pkt_parsed["tcp"]["dport"] = pkt.sprintf(r"%TCP.dport%")


	def recv_pkt_udp(self, pkt, pkt_parsed):
		pkt_parsed["udp"] = {}
		pkt_parsed["udp"]["sport"] = pkt.sprintf(r"%UDP.sport%")
		pkt_parsed["udp"]["dport"] = pkt.sprintf(r"%UDP.dport%")

		if DNS in pkt:
			if pkt_parsed["udp"]["sport"] == "domain":
				pkt.show()
			if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1:
				host = pkt.getlayer(DNS).qd.qname 
				ip = pkt.getlayer(DNS).an[0].rdata 
				print ip + ": " + host
				pkt_parsed["udp"]["layer7"] = {}
#				pkt_parsed["udp"]["layer7"]["dns-record"] = {}
				pkt_parsed["udp"]["layer7"]["dns-record"] = [ip, host]


	def recv_pkt_icmp(self, pkt, pkt_parsed):
		pkt_parsed["icmp"] = {}
		pkt_parsed["icmp"]["type"] = pkt.sprintf(r"%ICMP.type%")
		pkt_parsed["icmp"]["code"] = pkt.sprintf(r"%ICMP.code%")


