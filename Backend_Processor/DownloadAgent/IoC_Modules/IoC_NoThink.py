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

class IoC_NoThink(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
        print ("NoThink")
    #END Constructor

    def pull(self):
        NoThink_Threat = dict()
        # NoThink.org profiles 3 feeds, each is a simple text file where each line
        # is a seperate threat

        linkList = ['http://www.nothink.org/blacklist/blacklist_ssh_day.txt',
                    'http://www.nothink.org/blacklist/blacklist_telnet_day.txt',
                    'http://www.nothink.org/blacklist/blacklist_snmp_year.txt']

        individualFileItemCounter=0
        #sqlLogger=DataStore_Modules.DataStore_MySQL.dataStore_MySQL_Logger()

        for link_item in linkList:
            NoThinkThreat = dict()
            page = requests.get(link_item).text
            pulledList=page.split('\n')
            sqlComment=""
            for item in pulledList:
                if item.startswith('#'):
                    continue #just a comment line, skip it
                else:
                    if "ssh_day.txt" in link_item:
                        sqlComment="NoThink: ssh_day:scanner"
                    if "telnet_day.txt" in link_item:
                        sqlComment="NoThink: telnet_day:scanner"
                    if "snmp_year.txt" in link_item:
                        sqlComment="NoThink: snmp_year:scanner"
                    NoThinkThreat['threatkey'] = ""
                    NoThinkThreat['tlp'] = "white"
                    NoThinkThreat['reporttime'] = str(datetime.datetime.now())
                    NoThinkThreat['lasttime'] = str(datetime.datetime.now())
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
                    self.recordedThreats[self.threatCounter] = NoThinkThreat.copy()
                    self.threatCounter += 1
                    individualFileItemCounter+=1
                    NoThinkThreat.clear()
            self.processData(sqlComment)
#End NoThink

