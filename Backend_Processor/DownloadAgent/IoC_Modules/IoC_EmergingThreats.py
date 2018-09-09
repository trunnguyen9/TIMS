# SimpleIOC
# Darrell Miller
# darrellrhodesmiller@gmail.com
#
# Emerging Threats is a collection point for a number of security projects,
# mostly related to Intrusion Detection and network Traffic Analysis.
# Our primary project is the Emerging Threats Snort Ruleset contributed and
# maintained by the security community. This is just one of many projects.
# You can get information about many others on our AllProjects Page. We will
# make a home for any project that needs one and is related to security and
# network traffic. We are all open source and try to build our rulesets and
# projects with all users in mind. We have many satisfied users and contributors
# from the Corporate, Government, MSSP, and Home Users Worlds. There’s something
# here for everyone.
# http://docs.emergingthreats.net/bin/view/Main/EmergingFAQ
# produces a single txt file with one IP per line

import urllib.request
import urllib.parse
import json
from pprint import pprint
from datetime import datetime
import requests

import hashlib
from hashlib import md5
# from Backend_Processor.DownloadAgent.DataStore_Modules.DataStore_SQLite import SQLiteDataStore

class IoC_EmergingThreats:
	threatCounter = 0
	recordedThreats = dict()  # where threats are stored to put uploaded to database

	def __init__(self):
		print("Emerging Threats Constructor")

	# end constructor

	def pullEmergingThreats(self):
		print ("Pulling Emerging Threats .. shouldnt take long!")

		lineCount = 0
		EmergingThreat = dict()
		# sqlLogger = DataStore_Modules.DataStore_MySQL.dataStore_MySQL_Logger()

		# I think it might be worth making the URI an attribute of the class - Doug
		url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

		dresponse = urllib.request.urlopen(url)
		ddata = dresponse.read()  # a `bytes` object
		dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary

		dlist = dtext.split('\n')
		for item in dlist:
			if item:
				EmergingThreat['tlp'] = "green"
				EmergingThreat['lasttime'] = str(datetime.now())
				EmergingThreat['reporttime'] = str(datetime.now())
				EmergingThreat['icount'] = "1"
				EmergingThreat['itype'] = "ipv4"
				EmergingThreat['indicator'] = item
				EmergingThreat['cc'] = ""
				EmergingThreat['gps'] = ""
				EmergingThreat['asn'] = ""
				EmergingThreat['asn_desc'] = ""
				EmergingThreat['confidence'] = "9"
				EmergingThreat['description'] = ""
				EmergingThreat['tags'] = "malware"
				EmergingThreat['rdata'] = ""
				EmergingThreat['provider'] = "emergingthreats.net"
				EmergingThreat['entrytime']= str(datetime.now())
				EmergingThreat['enriched']=0

				tempKey = EmergingThreat['indicator'] + ":" + EmergingThreat['provider']
				EmergingThreat['threatkey'] = self.createMD5Key(tempKey)
				self.recordedThreats[self.threatCounter] = EmergingThreat.copy()
				self.threatCounter += 1
				EmergingThreat.clear()
			# end if
		print("Completed Emerging Threats!")
	# end pull Emerging Threats

	def createMD5Key(self, keystring):
		m = hashlib.md5()
		m.update(keystring.encode('utf-8'))
		md5string = m.hexdigest()
		return md5string
	# endcreateMD5Key

	def showThreats(self):
		pprint(self.recordedThreats)

	# end show Threats

	def getThreats(self):
		return self.recordedThreats.copy()
		# end getThreats

# end class IOC_EmergingThreats
