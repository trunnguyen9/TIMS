# emerging threats class with inheritance from IoC_Methods
from .IoC_Methods import IoC_Methods
import urllib.request
import urllib.parse
import json
from pprint import pprint
import datetime
from dateutil.parser import *
import requests

import hashlib
from hashlib import md5

class IoC_PhishTankv2(IoC_Methods):
    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
    #END Constructor

    def pull(self):
        print("Pulling Phish Tank Data, this could take a while, its pretty large")
        phishThreat = dict()  # temp spot to hold threat info to put in recordedThreats
        lineCount = 0

        # I think it might be worth making the URI an attribute of the class - Doug
        x = urllib.request.urlopen('http://data.phishtank.com/data/online-valid.json')
        results = x.read()
        results = results.decode("utf-8")
        # pprint (results)
        # print("----======----")
        jsonResults = json.loads(results)
        # sqlLogger=DataStore_Modules.DataStore_MySQL.dataStore_MySQL_Logger()

        for x in jsonResults:
            lineCount += 1
            phishThreat['threatkey'] = ""
            phishThreat['tlp'] = "green"

            dt = parse(x['submission_time'])

            phishThreat['lasttime'] = str(dt.strftime('%Y-%m-%d %H:%M:%S'))
            phishThreat['reporttime'] = str(datetime.datetime.now())
            phishThreat['icount'] = 1
            phishThreat['itype'] = "fqdn"
            phishThreat['indicator'] = x['url']
            phishThreat['cc'] = ""

            phishThreat['asn'] = ""
            phishThreat['asn_desc'] = ""
            phishThreat['confidence'] = 9
            phishThreat['description'] = "info:" + x['phish_detail_url'] + " target:" + x['target']
            phishThreat['tags'] = "phishing"
            phishThreat['rdata'] = "info:" + x['phish_detail_url'] + " target:" + x['target']
            phishThreat['provider'] = "PhishTank.com"
            phishThreat['gps'] = "lat and long will go here"
            phishThreat['enriched'] = 0

            #tempKey = phishThreat['indicator'] + ":" + phishThreat['provider']
            tempKey = phishThreat['indicator']
            phishThreat['threatkey'] = self.createMD5Key(tempKey)
            self.recordedThreats[self.threatCounter] = phishThreat.copy()
            self.threatCounter += 1
            phishThreat.clear()

        self.processData("PhishTank")
        print("Completed Phish Tank Ingest!")
#End EmergingThreatsv2
