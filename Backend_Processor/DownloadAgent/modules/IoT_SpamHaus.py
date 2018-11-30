# emerging threats class with inheritance from IoC_Methods
from .IoT_Methods import IoC_Methods
from .DataStore_SQLite import SQLiteDataStore
import urllib.request
import urllib.parse
import json
from pprint import pprint
import datetime
from dateutil.parser import *
import requests

import hashlib
from hashlib import md5

class IoC_SpamHaus(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database
    urlList = [
            "https://www.spamhaus.org/drop/drop.txt",
            "https://www.spamhaus.org/drop/dropv6.txt",
            "https://www.spamhaus.org/drop/edrop.txt"
        ]

    def __init__(self):
        IoC_Methods.__init__(self)
        # print ("SpamHaus")
        #self.multiThreader()
    #END Constructor

    def run(self):
        self.multiThreader()
    # end run

    def pull(self,urlItem):
        lineCount = 0
        SpamHausThreat = dict()
        allThreats = dict()

        linkItemCounter = 0

        logTitle="Spam Haus : " + urlItem

        # print (urlItem)
        self.TIMSlog['startTime'] = datetime.datetime.utcnow()
        dresponse = urllib.request.urlopen(urlItem)
        ddata = dresponse.read()  # a `bytes` object
        dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary
        dlist = dtext.split('\n')

        for x in dlist:
            if x.startswith(';'):
                #print("comment line")
                continue
            else:
                tempIndicator = x.split(';')
                SpamHausThreat['threatkey'] = ""
                SpamHausThreat['tlp'] = "green"
                SpamHausThreat['reporttime'] = str(datetime.datetime.utcnow())
                SpamHausThreat['lasttime'] = str(datetime.datetime.utcnow())
                SpamHausThreat['icount'] = 1
                SpamHausThreat['itype'] = "cidr"
                SpamHausThreat['indicator'] = tempIndicator[0].replace(' ', '')
                SpamHausThreat['cc'] = ""
                SpamHausThreat['asn'] = ""
                SpamHausThreat['asn_desc'] = ""
                SpamHausThreat['confidence'] = 9
                SpamHausThreat['description'] = "compromised host"
                SpamHausThreat['tags'] = "spam, hijacked"
                SpamHausThreat['rdata'] = ""
                SpamHausThreat['provider'] = "SpamHaus.com"
                SpamHausThreat['gps'] = "lat long go here"
                SpamHausThreat['enriched'] = 0

                tempKey = SpamHausThreat['indicator'] + ":" + SpamHausThreat['provider']
                SpamHausThreat['threatkey'] = self.createMD5Key(tempKey)
                allThreats[self.threatCounter] = SpamHausThreat.copy()
                self.threatCounter += 1
                linkItemCounter += 1
                SpamHausThreat.clear()

        SQLiteDS = SQLiteDataStore()
        dbConn = SQLiteDS.getDBConn()
        dbCursor = SQLiteDS.getDBCursor()
        self.addToDatabase(dbConn, dbCursor, allThreats)
        self.writeLogToDB(dbConn, dbCursor, logTitle)
        # do DB save and close
        # print("Complete!:", logTitle)
#End SpamHaus

