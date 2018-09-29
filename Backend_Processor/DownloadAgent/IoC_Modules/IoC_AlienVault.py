# AlienVault class with inheritance from IoC_Methods
from .IoC_Methods import IoC_Methods

import urllib.request
import urllib.parse
import json
from pprint import pprint
import datetime
import requests

import hashlib
from hashlib import md5

class IoC_AlienVault(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
        print("AlienVault")
    #END Constructor

    def pull(self):
        lineCount = 0
        AlienThreat = dict()
        # data source ,returns a binary datafeed of threats,data must be converted from
        # binary to utf-8 (standard text), then parsed.
        # Example line of data:
        # <IP Address>#<count>#<threat description>#<country of origin>#<area of origin>#<i have no idea GPS coordinates?>#<?>#<?>
        # 139.159.216.55#4#2#Malicious Host#CN#Shenzhen#22.5333003998,114.133300781#3
        linkList = [
            "https://reputation.alienvault.com/reputation.data"
        ]

        for itemLink in linkList:
            dresponse = urllib.request.urlopen(itemLink)
            ddata = dresponse.read()  # a `bytes` object
            dtext = ddata.decode('utf-8')  # a `str`; this step can't be used if data is binary
            dlist = dtext.split('\n')
            for x in dlist:
                tempIndicator = x.split('#')
                if len(tempIndicator) > 1:
                    AlienThreat['threatkey'] = ""
                    AlienThreat['tlp'] = "white"
                    AlienThreat['reporttime'] = str(datetime.datetime.now())
                    AlienThreat['lasttime'] = str(datetime.datetime.now())
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
                    self.recordedThreats[self.threatCounter] = AlienThreat.copy()
                    self.threatCounter += 1
                    AlienThreat.clear()
        self.processData("AlienVault")
    #End Pull

#End EmergingThreatsv2
