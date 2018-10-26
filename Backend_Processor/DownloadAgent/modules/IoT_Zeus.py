# emerging threats class with inheritance from IoC_Methods
from .DataStore_SQLite import SQLiteDataStore
from .IoT_Methods import IoC_Methods

import urllib.request
import urllib.parse
import json
from pprint import pprint
import datetime
from dateutil.parser import *
import requests

import hashlib
from hashlib import md5

class IoC_Zeus(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    urlList = [
        "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
        "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist",
        "https://zeustracker.abuse.ch/blocklist.php?download=compromised"
    ]

    def __init__(self):
        IoC_Methods.__init__(self)
        print ("Zeus Tracker")
        #self.multiThreader()
    #END Constructor

    def run(self):
        self.multiThreader()
    # end run

    def pull(self, urlItem):
        ZeusThreat = dict()
        allThreats=dict()

        linkItemCount=0

        print (urlItem)
        self.TIMSlog['startTime'] = datetime.datetime.utcnow()
        threatItype="type"
        page = requests.get(urlItem).text
        linesDownloaded=page.split('\n')
        logTitle="Zeus : " + urlItem
        for item in linesDownloaded:
            if item.startswith('#'):
                #print("BAD!", item)
                continue
            else:
                if urlItem=="https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist":
                    threatItype="fqdn"
                if urlItem=="https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist":
                    threatItype="ipv4"
                if urlItem=="https://zeustracker.abuse.ch/blocklist.php?download=compromised":
                    threatItype="fqdn"
                ZeusThreat['threatkey'] = ""
                ZeusThreat['tlp'] = "green"
                ZeusThreat['reporttime'] = str(datetime.datetime.utcnow())
                ZeusThreat['lasttime'] = str(datetime.datetime.utcnow())
                ZeusThreat['icount'] = 1
                ZeusThreat['itype'] = threatItype
                ZeusThreat['indicator'] = item
                ZeusThreat['cc'] = ""
                ZeusThreat['asn'] = ""
                ZeusThreat['asn_desc'] = ""
                ZeusThreat['confidence'] = 9
                ZeusThreat['description'] = "compromised host"
                ZeusThreat['tags'] = "zeus, botnet"
                ZeusThreat['rdata'] = ""
                ZeusThreat['provider'] = "Zeustracker.abuse.ch"
                ZeusThreat['gps'] = "lat and long will go here"
                ZeusThreat['enriched'] = 0

                tempKey = ZeusThreat['indicator'] + ":" + ZeusThreat['provider']
                ZeusThreat['threatkey'] = self.createMD5Key(tempKey)
                allThreats[self.threatCounter] = ZeusThreat.copy()
                self.threatCounter += 1
                linkItemCount+=1
                ZeusThreat.clear()
        #time.sleep(1)
        linkItemCount=0

        SQLiteDS = SQLiteDataStore()
        dbConn = SQLiteDS.getDBConn()
        dbCursor = SQLiteDS.getDBCursor()
        self.addToDatabase(dbConn, dbCursor, allThreats)
        self.writeLogToDB(dbConn, dbCursor, logTitle)
        # do DB save and close
        print("Complete!:", logTitle)

#End Zeus

