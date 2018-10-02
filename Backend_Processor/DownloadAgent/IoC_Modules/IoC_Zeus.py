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

class IoC_Zeus(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
        print ("Zeus Tracker")
    #END Constructor

    def pull(self):
        ZeusThreat = dict()
        linkList=[
            "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
            "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist",
            "https://zeustracker.abuse.ch/blocklist.php?download=compromised"
        ]

        linkItemCount=0
        for linkItem in linkList:
            print (linkItem)
            self.TIMSlog['startTime'] = datetime.datetime.now()
            threatItype="type"
            page = requests.get(linkItem).text
            linesDownloaded=page.split('\n')
            for item in linesDownloaded:
                if item.startswith('#'):
                    #print("BAD!", item)
                    continue
                else:
                    if linkItem=="https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist":
                        threatItype="fqdn"
                        sqlLoggerComment="Zeus : domain BlockList:Zeus Botnet"
                    if linkItem=="https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist":
                        threatItype="ipv4"
                        sqlLoggerComment="Zeus : IP BlockList:Zeus Botnet"
                    if linkItem=="https://zeustracker.abuse.ch/blocklist.php?download=compromised":
                        threatItype="fqdn"
                        sqlLoggerComment="Zeus : compromised BlockList:Zeus Botnet"
                    ZeusThreat['threatkey'] = ""
                    ZeusThreat['tlp'] = "green"
                    ZeusThreat['reporttime'] = str(datetime.datetime.now())
                    ZeusThreat['lasttime'] = str(datetime.datetime.now())
                    ZeusThreat['icount'] = 1
                    ZeusThreat['itype'] = threatItype
                    ZeusThreat['indicator'] = item
                    ZeusThreat['cc'] = ""
                    ZeusThreat['asn'] = ""
                    ZeusThreat['asn_desc'] = ""
                    ZeusThreat['confidence'] = 9
                    ZeusThreat['description'] = "compromised host"
                    ZeusThreat['tags'] = "zeus, botnet"
                    ZeusThreat['rdata'] = ""
                    ZeusThreat['provider'] = "Zeustracker.abuse.ch"
                    ZeusThreat['gps'] = "lat and long will go here"
                    ZeusThreat['enriched'] = 0

                    tempKey = ZeusThreat['indicator'] + ":" + ZeusThreat['provider']
                    ZeusThreat['threatkey'] = self.createMD5Key(tempKey)
                    self.recordedThreats[self.threatCounter] = ZeusThreat.copy()
                    self.threatCounter += 1
                    linkItemCount+=1
                    #pprint(ZeusThreat)
                    ZeusThreat.clear()
            #time.sleep(1)
            linkItemCount=0
            self.processData(sqlLoggerComment)
#End Zeus

