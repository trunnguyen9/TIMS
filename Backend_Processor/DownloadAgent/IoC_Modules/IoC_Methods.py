# SimpleIOC
# Darrell Miller
# darrellrhodesmiller@gmail.com
#
# The following code outlines uniform functions that are intended
# to be accesible by all specific IoC modules.  Certain Functions
# may be overwritten by specific-resource modules

import urllib.request
import urllib.parse
import json
from pprint import pprint
from datetime import datetime
import requests

import hashlib
from hashlib import md5

class IoC_Methods:
	threatCounter=0
	recordedThreats=dict() #where threats are stored to put uploaded to database
	uri = '' #Link to Location of Threats to be Extracted

	def __init__(self):
		print('Generic IoC Constructor')

	def pull(self):
		# I think it might be worth making the URI an attribute of the class - Doug
		x = urllib.request.urlopen(self.uri)
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