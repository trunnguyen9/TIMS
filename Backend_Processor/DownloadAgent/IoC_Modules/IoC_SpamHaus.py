# emerging threats class with inheritance from IoC_Methods
from .IoC_Methods import IoC_Methods
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

    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
        print ("SpamHaus")
    #END Constructor

    def pull(self):
        lineCount = 0
        SpamHausThreat = dict()

        # "https://www.spamhaus.org/drop/asndrop.txt",
        linkList = [
            "https://www.spamhaus.org/drop/drop.txt",
            "https://www.spamhaus.org/drop/dropv6.txt",
            "https://www.spamhaus.org/drop/edrop.txt"
        ]

        linkItemCounter = 0
        SQLLoggerComment = ""

        for itemLink in linkList:
            dresponse = urllib.request.urlopen(itemLink)
            ddata = dresponse.read()  # a `bytes` object
            dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary
            dlist = dtext.split('\n')

            for x in dlist:
                if x.startswith(';'):
                    #print("comment line")
                    continue
                else:
                    if "/drop.txt" in itemLink:
                        SQLLoggerComment = "SpamHaus : drop.txt: spam"
                    if "/dropv6.txt" in itemLink:
                        SQLLoggerComment = "SpamHaus : dropv6.txt: spam"
                    if "/edrop.txt" in itemLink:
                        SQLLoggerComment = "SpamHaus : edrop.txt: spam"
                    tempIndicator = x.split(';')
                    SpamHausThreat['threatkey'] = ""
                    SpamHausThreat['tlp'] = "green"
                    SpamHausThreat['reporttime'] = str(datetime.datetime.now())
                    SpamHausThreat['lasttime'] = str(datetime.datetime.now())
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
                    self.recordedThreats[self.threatCounter] = SpamHausThreat.copy()
                    self.threatCounter += 1
                    linkItemCounter += 1
                    SpamHausThreat.clear()
            self.processData(SQLLoggerComment)
#End SpamHaus

