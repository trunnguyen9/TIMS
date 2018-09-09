
import urllib.request
import urllib.parse
import json
from pprint import pprint
from datetime import datetime
import requests

import hashlib
from hashlib import md5
from Backend_Processor.DownloadAgent.DataStore_Modules.DataStore_SQLite import SQLiteDataStore


class IoC_Methods:
	threatCounter=0
	recordedThreats=dict() #where threats are stored to put uploaded to database
	uri = '' #Link to Location of Threats to be Extracted

	def __init__(self):

	def pull(self):
		print("Pulling Phish Tank Data, this could take a while, its pretty large")
		phishThreat=dict() #temp spot to hold threat info to put in recordedThreats
		lineCount = 0

		# I think it might be worth making the URI an attribute of the class - Doug
		x = urllib.request.urlopen('http://data.phishtank.com/data/online-valid.json')
		results = x.read()
		results = results.decode("utf-8")
		return results

	def showThreats(self):
		pprint(self.recordedThreats)
	# end show Threats

	def getThreats(self):
		return self.recordedThreats.copy()

	def createMD5Key(self, keystring):
		m = hashlib.md5()
		m.update(keystring.encode('utf-8'))
		md5string = m.hexdigest()
		return md5string
	# endcreateMD5Key