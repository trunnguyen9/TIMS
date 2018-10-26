# emerging threats class with inheritance from IoC_Methods
from .IoT_Methods import IoC_Methods
from .DataStore_SQLite import SQLiteDataStore

import urllib.request
import urllib.parse
import json
from pprint import pprint
from datetime import datetime
import requests

import hashlib
from hashlib import md5

class IoC_EmergingThreats(IoC_Methods):
    urlList = ["https://rules.emergingthreats.net/blockrules/compromised-ips.txt"]

    def __init__(self):
        IoC_Methods.__init__(self)
        #self.multiThreader()
    #END Constructor

    def run(self):
        self.multiThreader()
    # end run

    def pull(self,urlItem):
        print("Pulling Emerging Threats .. shouldnt take long!")

        lineCount = 0
        EmergingThreat = dict()
        allThreats = dict()
        logTitle = "Emerging Threats:" + urlItem

        dresponse = urllib.request.urlopen(urlItem)
        ddata = dresponse.read()  # a `bytes` object
        dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary

        dlist = dtext.split('\n')
        for item in dlist:
            if item:
                EmergingThreat['tlp'] = "green"
                EmergingThreat['lasttime'] = str(datetime.utcnow())
                EmergingThreat['reporttime'] = str(datetime.utcnow())
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
                EmergingThreat['entrytime'] = str(datetime.utcnow())
                EmergingThreat['enriched'] = 0

                #tempKey = EmergingThreat['indicator'] + ":" + EmergingThreat['provider']
                tempKey = EmergingThreat['indicator']
                #print ("TempKey:" , tempKey)
                EmergingThreat['threatkey'] = self.createMD5Key(tempKey)
                #print ("MD5 Key:", EmergingThreat['threatkey'])
                allThreats[self.threatCounter] = EmergingThreat.copy()
                self.threatCounter += 1
                EmergingThreat.clear()

        # connect to DB
        SQLiteDS = SQLiteDataStore()
        dbConn = SQLiteDS.getDBConn()
        dbCursor = SQLiteDS.getDBCursor()
        self.addToDatabase(dbConn, dbCursor, allThreats)
        self.writeLogToDB(dbConn, dbCursor, logTitle)
        # do DB save and close
        print("Complete!:", logTitle)
#End EmergingThreatsv2