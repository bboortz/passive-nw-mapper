#! /usr/bin/env python
import sys,os
from datetime import datetime
from logger import Logger
from pymongo import MongoClient
import json



class Mangler(object):
	client =  MongoClient("mongodb://localhost:27017")
	db = client.chameleon4
	coll_ips = db.ips


	def __init__(self):
		pass


	def insert_or_update(self, ip, mac=None, host=None):
		json = {}
		json["ip"] = ip
		json["mac"] = mac
		json["host"] = host

		cursor = self.coll_ips.find({"ip": "%s" % ip })
		if cursor.count() > 0:
			print "update"
			self.coll_ips.update_one( {"ip": "%s" % ip}, {
        "$set": {
            "mac": mac 
        }
    } )
		else:
			print "insert"
			self.coll_ips.insert_one(json)




class Layer2Mangler(Mangler):

	def __init__(self):
		self.coll_layer2 = self.db.layer2_packets


	def run(self):
		print "\n*** MANGLE LAYER2 PACKETS ***"
		cursor = self.coll_layer2.find()
		for doc in cursor:
			if "arp" in doc  and  doc["arp"]["operation"] == "response":
				self.insert_or_update(doc["arp"]["psrc"], doc["arp"]["hwsrc"])


			print doc
			self.coll_layer2.delete_one(doc)



class Layer3Mangler(Mangler):

	def __init__(self):
		self.coll_layer3 = self.db.layer3_packets


	def run(self):
		print "\n*** MANGLE LAYER3 PACKETS ***"
		cursor = self.coll_layer3.find()
		for doc in cursor:
			if "ip" in doc:
				if "ether" in doc:
					self.insert_or_update(doc["ip"]["src"], doc["ether"]["src"])
					self.insert_or_update(doc["ip"]["dst"], doc["ether"]["dst"])
				else:
					self.insert_or_update(doc["ip"]["src"])
					self.insert_or_update(doc["ip"]["dst"])
			elif "ipv6" in doc:
				if "ether" in doc:
					self.insert_or_update(doc["ipv6"]["src"], doc["ether"]["src"])
					self.insert_or_update(doc["ipv6"]["dst"], doc["ether"]["dst"])
				else:
					self.insert_or_update(doc["ipv6"]["src"])
					self.insert_or_update(doc["ipv6"]["dst"])

			self.coll_layer3.delete_one(doc)



class Layer4Mangler(Mangler):

	def __init__(self):
		self.coll_layer4 = self.db.layer4_packets


	def run(self):
		print "\n*** MANGLE LAYER4 PACKETS ***"
		cursor = self.coll_layer4.find()
		for doc in cursor:
			if "ip" in doc:
				if "ether" in doc:
					self.insert_or_update(doc["ip"]["src"], doc["ether"]["src"])
					self.insert_or_update(doc["ip"]["dst"], doc["ether"]["dst"])
				else:
					self.insert_or_update(doc["ip"]["src"])
					self.insert_or_update(doc["ip"]["dst"])
			elif "ipv6" in doc:
				if "ether" in doc:
					self.insert_or_update(doc["ipv6"]["src"], doc["ether"]["src"])
					self.insert_or_update(doc["ipv6"]["dst"], doc["ether"]["dst"])
				else:
					self.insert_or_update(doc["ipv6"]["src"])
					self.insert_or_update(doc["ipv6"]["dst"])

			self.coll_layer4.delete_one(doc)
			



if __name__ == '__main__':
	start_time = datetime.now()
	LOG = Logger()
	LOG.info("started at %s" % start_time)
	
	try:
		mangler = Layer2Mangler()
		mangler.run()
		mangler = Layer3Mangler()
		mangler.run()
		mangler = Layer4Mangler()
		mangler.run()
	except KeyboardInterrupt:
		LOG.info("KeyboardInterrupt received... exiting...")
		sys.exit()
