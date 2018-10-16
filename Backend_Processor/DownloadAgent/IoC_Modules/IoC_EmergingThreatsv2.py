# emerging threats class with inheritance from IoC_Methods
from .IoC_Methods import IoC_Methods

import urllib.request
import urllib.parse
import json
from pprint import pprint
from datetime import datetime
import requests

import hashlib
from hashlib import md5

class IoC_EmergingThreatsv2(IoC_Methods):
    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
    #END Constructor

    def pull(self):
        print("Pulling Emerging Threats .. shouldnt take long!")

        lineCount = 0
        EmergingThreat = dict()
        # sqlLogger = DataStore_Modules.DataStore_MySQL.dataStore_MySQL_Logger()

        # I think it might be worth making the URI an attribute of the class - Doug
        url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

        dresponse = urllib.request.urlopen(url)
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
                self.recordedThreats[self.threatCounter] = EmergingThreat.copy()
                self.threatCounter += 1
                EmergingThreat.clear()
        self.processData("Emerging Threats")
#End EmergingThreatsv2
