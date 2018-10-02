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

class IoC_SANsEDU(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
        print ("SANS.EDU")
    #END Constructor

    def pull(self):
        threatCounter = 0
        recordedThreats = dict()  # where threats are stored to put uploaded to database

        lineCount = 0
        SANS_Threat = dict()
        fileItemCount = 0
        loggerComment = ""

        linkList = [
            "https://isc.sans.edu/feeds/suspiciousdomains_Low.txt",
            "https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt",
            "https://isc.sans.edu/feeds/suspiciousdomains_High.txt",
            "https://isc.sans.edu/feeds/block.txt"
        ]

        for linkItem in linkList:
            self.TIMSlog['startTime']=datetime.datetime.now()
            dresponse = urllib.request.urlopen(linkItem)
            ddata = dresponse.read()  # a `bytes` object
            dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary
            dlist = dtext.split('\n')
            if "Low" in linkItem:
                loggerComment = "SANS: low:malware"
            if "Medium" in linkItem:
                loggerComment = "SANS: medium:malware"
            if "High" in linkItem:
                loggerComment = "SANS: high:malware"
            if "block" in linkItem:
                loggerComment = "SANS: block:malware"
            for x in dlist:
                if x.startswith('#'):
                    #print("comment line")
                    continue
                else:
                    SANS_Threat['threatkey'] = ""
                    SANS_Threat['tlp'] = "green"
                    SANS_Threat['reporttime'] = str(datetime.datetime.now())
                    SANS_Threat['lasttime'] = str(datetime.datetime.now())
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
                    self.recordedThreats[self.threatCounter] = SANS_Threat.copy()
                    self.threatCounter += 1
                    SANS_Threat.clear()
                    fileItemCount += 1
            fileItemCount = 0
            print (loggerComment)
            self.processData(loggerComment)
#End SANsEDU

