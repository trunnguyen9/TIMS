# emerging threats class with inheritance from IoC_Methods
from .IoT_Methods import IoC_Methods
from .DataStore_SQLite import SQLiteDataStore

import urllib.parse
import json
from pprint import pprint
import datetime
from dateutil.parser import *
import requests

import hashlib
from hashlib import md5

class IoC_PhishTank(IoC_Methods):
    apiKey = "75bce15aa97bb53853e9d74af709a4c04cc854d473d0203733f677fca1938aaa"
    urlPart1 = "http://data.phishtank.com/data/"
    urlPart3 = "/online-valid.json"
    fullUrl = urlPart1 + apiKey + urlPart3
    urlList = [fullUrl]


    def __init__(self):
        IoC_Methods.__init__(self)
        print("PhishTank")
    #END Constructor

    def run(self):
        self.multiThreader()
    # end run

    def pull(self,urlItem):
        allThreats = dict()
        print("Pulling Phish Tank Data, this could take a while, its pretty large")
        phishThreat = dict()  # temp spot to hold threat info to put in recordedThreats
        lineCount = 0
        logTitle = "PhishTank : " + urlItem
        # I think it might be worth making the URI an attribute of the class - Doug
        x = urllib.request.urlopen(urlItem)
        print ("x",x)
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
            phishThreat['reporttime'] = str(datetime.datetime.utcnow())
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
            allThreats[self.threatCounter] = phishThreat.copy()
            self.threatCounter += 1
            phishThreat.clear()

        # connect to DB
        SQLiteDS = SQLiteDataStore()
        dbConn = SQLiteDS.getDBConn()
        dbCursor = SQLiteDS.getDBCursor()
        self.addToDatabase(dbConn, dbCursor, allThreats)
        self.writeLogToDB(dbConn, dbCursor, logTitle)
        # do DB save and close
        print("Complete!:", logTitle)
        print("Completed Phish Tank Ingest!")
#End EmergingThreatsv2
