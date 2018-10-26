# Feodotracker class with inheritance from IoC_Methods
from .IoT_Methods import IoC_Methods
from .DataStore_SQLite import SQLiteDataStore

import urllib.request
import urllib.parse
import datetime
import pprint

class IoC_Feodotracker(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    urlList = [
        "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist",
        "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist"
    ]

    def __init__(self):
        IoC_Methods.__init__(self)
        print("FeodoTracker")
        #self.multiThreader()
    #END Constructor

    def run(self):
        self.multiThreader()
    # end run

    def pull(self,urlItem):
        lineCount = 0
        feodoThreat = dict()
        allThreats = dict()
        logTitle = "FedoTracker:" + urlItem

        print (urlItem)
        self.TIMSlog['startTime']=datetime.datetime.utcnow()
        threatConfidence = 0
        self.threatCounter=0
        lineCount=0
        threatTags = "feodo,botnet"


        dresponse = urllib.request.urlopen(urlItem)
        ddata = dresponse.read()  # a `bytes` object
        dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary
        dlist = dtext.split('\n')
        # print (dlist)

        if urlItem == "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist":
            threatItype = "ipv4"
            threatConfidence = 8
            threatLoggerComment = "ipblocklist"

        if urlItem == "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist":
            threatItype = "fqdn"
            threatConfidence = 6
            threatLoggerComment = "domainblocklist"

        for x in dlist:
            if x.startswith('#'):
                #print ("skipping line, just a comment")
                continue  # comment line, just skipping it
            else:
                feodoThreat['threatkey'] = ""
                feodoThreat['tlp'] = "green"
                feodoThreat['reporttime'] = str(datetime.datetime.utcnow())
                feodoThreat['lasttime'] = str(datetime.datetime.utcnow())
                feodoThreat['icount'] = 1
                feodoThreat['itype'] = threatItype
                feodoThreat['indicator'] = x
                feodoThreat['cc'] = ""
                feodoThreat['gps']=""
                feodoThreat['asn'] = ""
                feodoThreat['asn_desc'] = ""
                feodoThreat['confidence'] = threatConfidence
                feodoThreat['description'] = " Feodo"
                feodoThreat['tags'] = threatTags
                feodoThreat['rdata'] = ""
                feodoThreat['provider'] = "feodotracker.abuse.ch"
                feodoThreat['enriched'] = 0

                tempKey = feodoThreat['indicator']
                feodoThreat['threatkey'] = self.createMD5Key(tempKey)
                allThreats[self.threatCounter] = feodoThreat.copy()
                self.threatCounter += 1
                feodoThreat.clear()
        # connect to DB
        SQLiteDS = SQLiteDataStore()
        dbConn = SQLiteDS.getDBConn()
        dbCursor = SQLiteDS.getDBCursor()
        self.addToDatabase(dbConn, dbCursor, allThreats)
        self.writeLogToDB(dbConn, dbCursor, logTitle)
        # do DB save and close
        print("Complete!:", logTitle)
    #End Pull
#End EmergingThreatsv2
