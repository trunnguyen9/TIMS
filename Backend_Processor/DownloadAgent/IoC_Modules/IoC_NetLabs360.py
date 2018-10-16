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

class IoC_NetLabs360(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
        print ("NetLab360")
    #END Constructor

    def pull(self):
        NetLabThreat = dict()
        linkList=[
            "http://data.netlab.360.com/feeds/dga/bamital.txt",
            "http://data.netlab.360.com/feeds/dga/banjori.txt",
            "http://data.netlab.360.com/feeds/dga/banjori.txt",
            "http://data.netlab.360.com/feeds/dga/chinad.txt",
            "http://data.netlab.360.com/feeds/dga/conficker.txt",
            "http://data.netlab.360.com/feeds/dga/cryptolocker.txt",
            "http://data.netlab.360.com/feeds/dga/dyre.txt",
            "http://data.netlab.360.com/feeds/dga/fobber.txt",
            "http://data.netlab.360.com/feeds/dga/gameover.txt",
            "http://data.netlab.360.com/feeds/dga/gspy.txt",
            "http://data.netlab.360.com/feeds/dga/locky.txt",
            "http://data.netlab.360.com/feeds/dga/madmax.txt",
            "http://data.netlab.360.com/feeds/dga/mirai.txt",
            "http://data.netlab.360.com/feeds/dga/murofet.txt",
            "http://data.netlab.360.com/feeds/dga/necurs.txt",
            "http://data.netlab.360.com/feeds/dga/nymaim.txt",
            "http://data.netlab.360.com/feeds/dga/proslikefan.txt",
            "http://data.netlab.360.com/feeds/dga/pykspa.txt",
            "http://data.netlab.360.com/feeds/dga/qadars.txt",
            "http://data.netlab.360.com/feeds/dga/ramnit.txt",
            "http://data.netlab.360.com/feeds/dga/ranbyus.txt",
            "http://data.netlab.360.com/feeds/dga/rovnix.txt",
            "http://data.netlab.360.com/feeds/dga/shifu.txt",
            "http://data.netlab.360.com/feeds/dga/simda.txt",
            "http://data.netlab.360.com/feeds/dga/symmi.txt",
            "http://data.netlab.360.com/feeds/dga/tempedreve.txt",
            "http://data.netlab.360.com/feeds/dga/tinba.txt",
            "http://data.netlab.360.com/feeds/dga/tofsee.txt",
            "http://data.netlab.360.com/feeds/dga/vawtrak.txt",
            "http://data.netlab.360.com/feeds/dga/vidro.txt"
        ]

        linkItemCount=0
        for linkItem in linkList:
            self.recordedThreats.clear()
            threatItype="fqdn"
            page = requests.get(linkItem).text
            linesDownloaded=page.split('\n')
            self.TIMSlog['startTime'] = datetime.datetime.utcnow()
            for item in linesDownloaded:
                if item.startswith('#'):
                    continue
                else:
                    sqlLoggerComment="NetLab : " + linkItem
                    NetLabThreat['threatkey'] = ""
                    NetLabThreat['tlp'] = "green"
                    NetLabThreat['reporttime'] = str(datetime.datetime.utcnow())
                    NetLabThreat['lasttime'] = str(datetime.datetime.utcnow())
                    NetLabThreat['icount'] = 1
                    NetLabThreat['itype'] = threatItype
                    NetLabThreat['indicator'] = item
                    NetLabThreat['cc'] = ""
                    NetLabThreat['asn'] = ""
                    NetLabThreat['asn_desc'] = ""
                    NetLabThreat['confidence'] = 9
                    NetLabThreat['description'] = "compromised host"
                    NetLabThreat['tags'] = "zeus, botnet"
                    NetLabThreat['rdata'] = ""
                    NetLabThreat['provider'] = "NetLabs360"
                    NetLabThreat['gps'] = "lat and long will go here"
                    NetLabThreat['enriched'] = 0

                    tempKey = NetLabThreat['indicator'] + ":" + NetLabThreat['provider']
                    NetLabThreat['threatkey'] = self.createMD5Key(tempKey)
                    self.recordedThreats[self.threatCounter] = NetLabThreat.copy()
                    self.threatCounter += 1
                    linkItemCount+=1
                    #pprint(NetLabThreat)
                    NetLabThreat.clear()
            #time.sleep(1)
            linkItemCount=0
            print(sqlLoggerComment," : ",len(self.recordedThreats))
            self.processData(sqlLoggerComment)
#End NetLab360

