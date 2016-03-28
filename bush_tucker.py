#! /usr/bin/env python
import sys,os
from datetime import datetime
from logger import Logger
from pymongo import MongoClient
import json



class Mangler(object):
	client =  MongoClient("mongodb://localhost:27017")
	db = client.chameleon4

	def __init__(self):
		self.client =  MongoClient("mongodb://localhost:27017")
		self.db = self.client.chameleon4


class Layer3Mangler(Mangler):

	def __init__(self):
		self.coll_layer3 = self.db.layer3_packets
		self.coll_ips = self.db.ips


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
		self.coll_ips = self.db.ips


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
		mangler = Layer4Mangler()
		mangler.run()
		mangler = Layer3Mangler()
		mangler.run()
	except KeyboardInterrupt:
		LOG.info("KeyboardInterrupt received... exiting...")
		sys.exit()
