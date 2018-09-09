# SimpleIOC
# Darrell Miller
# darrellrhodesmiller@gmail.com
#
# PhishTank is a free community site where anyone can submit, verify,
# track and share phishing data.
# www.phishtank.com
# phishtank returns a JSON file when a request is made. This JSON
# typically around 6 megs of phishing data

import urllib.request
import urllib.parse
import json
from pprint import pprint
import datetime
from dateutil.parser import *
import requests

import hashlib
from hashlib import md5

import time
#import DataStore_Modules

class IoC_PhishTank:

    threatCounter=0
    recordedThreats=dict() #where threats are stored to put uploaded to database

    def __init__(self):
        print ("constructor")
    #end constructor

    def pullPhishtank(self):
        phishThreat=dict() #temp spot to hold threat info to put in recordedThreats
        lineCount = 0

        x = urllib.request.urlopen('http://data.phishtank.com/data/online-valid.json')
        results = x.read()
        results = results.decode("utf-8")
        # pprint (results)
        # print("----======----")
        jsonResults = json.loads(results)
        #sqlLogger=DataStore_Modules.DataStore_MySQL.dataStore_MySQL_Logger()

        for x in jsonResults:
            lineCount += 1
            phishThreat['threatkey']=""
            phishThreat['tlp']="green"

            dt= parse(x['submission_time'])

            phishThreat['lasttime']=str(dt.strftime('%Y-%m-%d %H:%M:%S'))
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
            phishThreat['enriched']=0

            tempKey=phishThreat['indicator']+":"+phishThreat['provider']
            phishThreat['threatkey']=self.createMD5Key(tempKey)
            self.recordedThreats[self.threatCounter]=phishThreat.copy()
            self.threatCounter+=1
            phishThreat.clear()

        print("lineCount", lineCount)
        #sqlLogger.writeToLog("Phishtank",str(self.threatCounter),"phishing")
    #end pullPhishtank

    def showThreats(self):
        pprint(self.recordedThreats)
    #end show Threats

    def getThreats(self):
        return self.recordedThreats.copy()
        # end getThreats

    def createMD5Key(self, keystring):
        m = hashlib.md5()
        m.update(keystring.encode('utf-8'))
        md5string = m.hexdigest()
        return md5string
    #endcreateMD5Key
#end class IOC_PhishTank
