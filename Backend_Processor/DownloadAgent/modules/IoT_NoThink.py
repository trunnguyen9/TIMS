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

class IoC_NoThink(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    urlList = ['http://www.nothink.org/blacklist/blacklist_ssh_day.txt',
                'http://www.nothink.org/blacklist/blacklist_telnet_day.txt',
                'http://www.nothink.org/blacklist/blacklist_snmp_year.txt']

    def __init__(self):
        IoC_Methods.__init__(self)
        # print ("NoThink")
    #END Constructor

    def run(self):
        self.multiThreader()
    # end run

    def pull(self,urlItem):
        # NoThink_Threat = dict()
        allThreats=dict()

        logTitle = "NoThink : " + urlItem

        # NoThink.org profiles 3 feeds, each is a simple text file where each line
        # is a seperate threat

        individualFileItemCounter=0
        self.TIMSlog['startTime'] = datetime.datetime.utcnow()
        NoThinkThreat = dict()
        page = requests.get(urlItem).text
        pulledList=page.split('\n')
        for item in pulledList:
            if item.startswith('#'):
                continue #just a comment line, skip it
            else:
                NoThinkThreat['threatkey'] = ""
                NoThinkThreat['tlp'] = "white"
                NoThinkThreat['reporttime'] = str(datetime.datetime.utcnow())
                NoThinkThreat['lasttime'] = str(datetime.datetime.utcnow())
                NoThinkThreat['icount'] = 1
                NoThinkThreat['itype'] = "ipv4"
                NoThinkThreat['indicator'] = item
                NoThinkThreat['cc'] = ""
                NoThinkThreat['asn'] = ""
                NoThinkThreat['asn_desc'] = ""
                NoThinkThreat['confidence'] = 7
                NoThinkThreat['description'] = "compromised host"
                NoThinkThreat['tags'] = "Scanner"
                NoThinkThreat['rdata'] = ""
                NoThinkThreat['provider'] = "NoThink"
                NoThinkThreat['gps'] = "long and lat will go here"
                NoThinkThreat['enriched'] = 0

                tempKey = NoThinkThreat['indicator'] + ":" + NoThinkThreat['provider']
                NoThinkThreat['threatkey'] = self.createMD5Key(tempKey)
                allThreats[self.threatCounter] = NoThinkThreat.copy()
                self.threatCounter += 1
                individualFileItemCounter+=1
                NoThinkThreat.clear()
        # connect to DB
        SQLiteDS = SQLiteDataStore()
        dbConn = SQLiteDS.getDBConn()
        dbCursor = SQLiteDS.getDBCursor()
        self.addToDatabase(dbConn, dbCursor, allThreats)
        self.writeLogToDB(dbConn, dbCursor, logTitle)
        # do DB save and close
#End NoThink

