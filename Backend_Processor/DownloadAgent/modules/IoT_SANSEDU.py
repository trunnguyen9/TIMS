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

class IoC_SANsEDU(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database
    urlList = [
            "https://isc.sans.edu/feeds/suspiciousdomains_Low.txt",
            "https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt",
            "https://isc.sans.edu/feeds/suspiciousdomains_High.txt",
            "https://isc.sans.edu/feeds/block.txt"
        ]

    def __init__(self):
        IoC_Methods.__init__(self)
        # print ("SANS.EDU")
        #self.multiThreader()
    #END Constructor

    def run(self):
        self.multiThreader()
    # end run

    def pull(self,urlItem):
        threatCounter = 0
        recordedThreats = dict()  # where threats are stored to put uploaded to database
        allThreats=dict()

        lineCount = 0
        SANS_Threat = dict()
        fileItemCount = 0
        logTitle = "SANS.EDU : " + urlItem

        self.TIMSlog['startTime']=datetime.datetime.utcnow()
        dresponse = urllib.request.urlopen(urlItem)
        ddata = dresponse.read()  # a `bytes` object
        dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary
        dlist = dtext.split('\n')

        for x in dlist:
            if x.startswith('#'):
                #print("comment line")
                continue
            else:
                SANS_Threat['threatkey'] = ""
                SANS_Threat['tlp'] = "green"
                SANS_Threat['reporttime'] = str(datetime.datetime.utcnow())
                SANS_Threat['lasttime'] = str(datetime.datetime.utcnow())
                SANS_Threat['icount'] = 1
                SANS_Threat['itype'] = "fdnq"
                SANS_Threat['indicator'] = x
                SANS_Threat['cc'] = ""
                SANS_Threat['asn'] = ""
                SANS_Threat['asn_desc'] = ""
                SANS_Threat['confidence'] = 7
                SANS_Threat['description'] = ""
                SANS_Threat['tags'] = "Malware, suspicious"
                SANS_Threat['rdata'] = ""
                SANS_Threat['provider'] = "ics.sans.edu"
                SANS_Threat['gps'] = "long and lat go here"
                SANS_Threat['enriched'] = 0

                tempKey = SANS_Threat['indicator'] + ":" + SANS_Threat['provider']
                SANS_Threat['threatkey'] = self.createMD5Key(tempKey)
                allThreats[self.threatCounter] = SANS_Threat.copy()
                self.threatCounter += 1
                SANS_Threat.clear()
                fileItemCount += 1
            fileItemCount = 0
            # connect to DB
        SQLiteDS = SQLiteDataStore()
        dbConn = SQLiteDS.getDBConn()
        dbCursor = SQLiteDS.getDBCursor()
        self.addToDatabase(dbConn, dbCursor, allThreats)
        self.writeLogToDB(dbConn, dbCursor, logTitle)
        # do DB save and close
        # print("Complete!:", logTitle)
#End SANsEDU

