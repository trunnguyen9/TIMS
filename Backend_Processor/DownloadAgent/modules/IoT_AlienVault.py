# AlienVault class with inheritance from IoC_Methods
from .IoT_Methods import IoC_Methods
import urllib.request
import urllib.parse
import json
from pprint import pprint
import datetime
import requests

import hashlib
from hashlib import md5
from .DataStore_SQLite import SQLiteDataStore

class IoC_AlienVault(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    urlList = [
        "https://reputation.alienvault.com/reputation.data"
    ]

    def __init__(self):
        IoC_Methods.__init__(self)
        # print("AlienVault")
        #self.multiThreader()
    #END Constructor

    def run(self):
        self.multiThreader()
    # end run

    def pull(self, urlItem):
        lineCount = 0
        AlienThreat = dict()
        allThreats = dict()
        logTitle = "AlienVault:" + urlItem
        # data source ,returns a binary datafeed of threats,data must be converted from
        # binary to utf-8 (standard text), then parsed.
        # Example line of data:
        # <IP Address>#<count>#<threat description>#<country of origin>#<area of origin>#<i have no idea GPS coordinates?>#<?>#<?>
        # 139.159.216.55#4#2#Malicious Host#CN#Shenzhen#22.5333003998,114.133300781#3

        dresponse = urllib.request.urlopen(urlItem)
        ddata = dresponse.read()  # a `bytes` object
        dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary
        dlist = dtext.split('\n')
        for x in dlist:
            tempIndicator = x.split('#')
            if len(tempIndicator) > 1:
                AlienThreat['threatkey'] = ""
                AlienThreat['tlp'] = "white"
                AlienThreat['reporttime'] = str(datetime.datetime.utcnow())
                AlienThreat['lasttime'] = str(datetime.datetime.utcnow())
                AlienThreat['icount'] = 1
                AlienThreat['itype'] = "ipv4"
                AlienThreat['indicator'] = tempIndicator[0]
                AlienThreat['cc'] = tempIndicator[4]
                AlienThreat['gps'] = ""
                AlienThreat['asn'] = "5"
                AlienThreat['asn_desc'] = ""
                AlienThreat['confidence'] = 7
                AlienThreat['description'] = tempIndicator[3]
                AlienThreat['tags'] = "malware, suspicious"
                AlienThreat['rdata'] = ""
                AlienThreat['provider'] = "Alienvault"
                AlienThreat['enriched'] = 0

                #tempKey = AlienThreat['indicator'] + ":" + AlienThreat['provider']
                tempKey = AlienThreat['indicator']
                AlienThreat['threatkey'] = self.createMD5Key(tempKey)
                allThreats[self.threatCounter] = AlienThreat.copy()
                self.threatCounter += 1
                AlienThreat.clear()

        # connect to DB
        # print ("Creating Database Connection:")
        SQLiteDS = SQLiteDataStore()
        dbConn = SQLiteDS.getDBConn()
        dbCursor = SQLiteDS.getDBCursor()
        self.addToDatabase(dbConn, dbCursor, allThreats)
        self.writeLogToDB(dbConn, dbCursor, logTitle)
        # do DB save and close
        # print("Complete!:", logTitle)
    #End Pull

#End EmergingThreatsv2
