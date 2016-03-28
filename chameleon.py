#! /usr/bin/env python
import sys,os
from datetime import datetime
from scapy.all import sniff
from callbacks import Callbacks

iface='venet0:0'

class Sniffer(object):

	def __init__(self):
		self.timeout = 120
		self.count = 1000
		self.filter = ""
		self.iface = None
#		self.iface = "venet0:0"
		self.callbacks = Callbacks()


	def run(self):
		print "\n*** SNIFFING ***"
		p = sniff(prn=self.callbacks.cb_recv_pkt, iface=self.iface, timeout=self.timeout, count=self.count, filter=self.filter)

		print "\n*** SUMMARY ***"
		print p.nsummary()



class Logger(object):

	def __init__(self):
		pass

	def info(self, msg):
		print("[*] %s" % msg)	



if __name__ == '__main__':
	start_time = datetime.now()
	LOG = Logger()
	LOG.info("started at %s" % start_time)
	
	try:

		sniffer = Sniffer()
		sniffer.run()
	except KeyboardInterrupt:
		LOG.info("KeyboardInterrupt received... exiting...")
		sys.exit()
