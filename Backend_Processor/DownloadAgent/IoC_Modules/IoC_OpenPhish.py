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

class IoC_OpenPhish(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
        print ("OpenPhish")
    #END Constructor

    def pull(self):
        lineCount = 0
        OpenPhishThreat = dict()
        # sqlLogger=DataStore_Modules.DataStore_MySQL.dataStore_MySQL_Logger()
        url = "https://openphish.com/feed.txt"

        # Openphish returns a straight textfile with a list of known malicious websites
        # each line is a seperate threat, each line is a web address
        # Example:
        # <weblink>
        # https://www.badbadwebsite.com/dontgohere

        dresponse = urllib.request.urlopen(url)
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
                self.recordedThreats[self.threatCounter] = OpenPhishThreat.copy()
                self.threatCounter += 1
                OpenPhishThreat.clear()
            # end if
        self.processData("OpenPhish")
    # end pull OpenPhish
#End NoThink