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

class IoC_OpenPhish(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database
    urlList = ["https://openphish.com/feed.txt"]
    def __init__(self):
        IoC_Methods.__init__(self)
        # print ("OpenPhish")
        #self.multiThreader()
    #END Constructor

    def run(self):
        self.multiThreader()
    # end run

    def pull(self,urlItem):
        lineCount = 0
        OpenPhishThreat = dict()
        allThreats= dict()
        logTitle = "OpenPhish : " + urlItem
        # sqlLogger=DataStore_Modules.DataStore_MySQL.dataStore_MySQL_Logger()

        # Openphish returns a straight textfile with a list of known malicious websites
        # each line is a seperate threat, each line is a web address
        # Example:
        # <weblink>
        # https://www.badbadwebsite.com/dontgohere

        dresponse = urllib.request.urlopen(urlItem)
        ddata = dresponse.read()  # a `bytes` object
        dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary
        dlist = dtext.split('\n')

        for item in dlist:
            if item:
                OpenPhishThreat['tlp'] = "green"
                OpenPhishThreat['lasttime'] = str(datetime.datetime.utcnow())
                OpenPhishThreat['reporttime'] = str(datetime.datetime.utcnow())
                OpenPhishThreat['icount'] = 1
                OpenPhishThreat['itype'] = "fdnq"
                OpenPhishThreat['indicator'] = item
                OpenPhishThreat['cc'] = ""
                OpenPhishThreat['asn'] = ""
                OpenPhishThreat['asn_desc'] = ""
                OpenPhishThreat['confidence'] = "9"
                OpenPhishThreat['description'] = ""
                OpenPhishThreat['tags'] = "phishing, openphish"
                OpenPhishThreat['rdata'] = ""
                OpenPhishThreat['provider'] = "openphish.com"
                OpenPhishThreat['gps'] = "lat and long go here"
                OpenPhishThreat['enriched'] = 0

                tempKey = OpenPhishThreat['indicator'] + ":" + OpenPhishThreat['provider']
                OpenPhishThreat['threatkey'] = self.createMD5Key(tempKey)
                allThreats[self.threatCounter] = OpenPhishThreat.copy()
                self.threatCounter += 1
                OpenPhishThreat.clear()
            # end if
        # end for
        # connect to DB
        SQLiteDS = SQLiteDataStore()
        dbConn = SQLiteDS.getDBConn()
        dbCursor = SQLiteDS.getDBCursor()
        self.addToDatabase(dbConn, dbCursor, allThreats)
        self.writeLogToDB(dbConn, dbCursor, logTitle)
        # do DB save and close
        # print("Complete!:", logTitle)

    # end pull OpenPhish
#End NoThink