# CSIRTH class with inheritance from IoC_Methods
from .IoC_Methods import IoC_Methods
import urllib.request
import urllib.parse
import json
from pprint import pprint
import datetime
import requests

import hashlib
from hashlib import md5

from csirtgsdk.client import Client
from csirtgsdk.feed import Feed
from pprint import pprint


class IoC_CSIRTG(IoC_Methods):
    threatCounter = 0
    recordedThreats = dict()  # where threats are stored to put uploaded to database

    def __init__(self,conn):
        IoC_Methods.__init__(self,conn)
        print("CSIRTG")
    #END Constructor

    def pull(self):
        lineCount = 0
        CSIRTGThreat = dict()
        csirtgAll = dict()
        csirtgIndicatorDict = dict()
        indicatorCounter = 0

        remote = 'https://csirtg.io/api'
        remote2 = 'https://csirtg.io/api/users/csirtgadgets/feeds'
        token = '3c6e9294747b06a841eadc8b8b2e73be'
        token = '1c277786ae04719eb71d9e5d8e9c98be'
        verify_ssl = True

        user = 'csirtgadgets'
        feed = 'uce-urls'
        count = 0
        dataDict = dict()

        # Initiate client object
        cli = Client(remote=remote, token=token, verify_ssl=verify_ssl)

        # Return a list of feeds (per user)
        ret = Feed(cli).index(user)

        # pprint the returned data structure
        #pprint(ret)
        try :
            for feedItem in ret:
                feed = feedItem['name']
                ret = Feed(cli).show(user, feed, limit=None)
                count += 1
                dataDict[feed] = ret.copy()
                print ("   - Getting feed item: " + str(count))
                #if count == 5:
                #    break
            #pprint(dataDict)
            print ("copying all feeds into JSON")
            js = json.dumps(dataDict)

            print ("saving JSON")
            fp = open("CSIRTG.JSON", "w")
            fp.write(js)
            fp.close()

            self.readFile()
        except:
            print ("ERROR: CSIRTG ")
    #End Pull

    def convertTime(self, strTime):
        #2017-11-28 20:23:58 UTC
        #format "%Y-%m-%d %H:%M:%S"
        strTime=strTime.replace(" UTC","")
        return str(datetime.datetime.strptime(strTime, "%Y-%m-%d %H:%M:%S"))
    #end convertTime

    def readFile(self):
        csirtgAll=dict()
        csirtgIndicatorDict=dict()
        indicatorCounter=0
        CSIRTGThreat=dict()

        with open('CSIRTG.JSON','r') as f:
            csirtgData=json.load(f)
        for x in csirtgData:
            print(":", x)
            print ("    User:",csirtgData[x]['user'])
            print ("    Description:",csirtgData[x]['description'])
            print ("    License:",csirtgData[x]['license'])
            print ("    created_at:",csirtgData[x]['created_at'])
            print ("    updated_at:",csirtgData[x]['updated_at'])
            print ("    indicators:", len(csirtgData[x]['indicators']))
            for y in csirtgData[x]['indicators']:
                csirtgIndicatorDict[indicatorCounter]=y.copy()
                indicatorCounter+=1
        print("-----------------====================-----------------------")
        for x in csirtgIndicatorDict:
            for y in csirtgIndicatorDict[x]:
                CSIRTGThreat['tlp']="green"
                CSIRTGThreat['lasttime'] = str(datetime.datetime.now())
                CSIRTGThreat['reporttime'] = str(datetime.datetime.now())
                CSIRTGThreat['icount'] = csirtgIndicatorDict[x]['count']
                CSIRTGThreat['itype'] = "ipv4"
                CSIRTGThreat['indicator'] = csirtgIndicatorDict[x]['indicator']
                CSIRTGThreat['cc'] = ""
                CSIRTGThreat['gps'] = ""
                CSIRTGThreat['asn'] = ""
                CSIRTGThreat['asn_desc'] = ""
                CSIRTGThreat['confidence'] = '9'
                CSIRTGThreat['description'] = str(x) +" : "+ csirtgIndicatorDict[x]['description']
                CSIRTGThreat['tags'] = str(csirtgIndicatorDict[x]['tags'])
                CSIRTGThreat['rdata'] = "ports" + str(csirtgIndicatorDict[x]['portlist'])
                CSIRTGThreat['provider'] = "CSIRTGThreats.net"
                CSIRTGThreat['enriched']=0

                tempKey = CSIRTGThreat['indicator']
                CSIRTGThreat['threatkey'] = self.createMD5Key(tempKey)
                self.recordedThreats[self.threatCounter]=CSIRTGThreat.copy()
                self.threatCounter+=1
                CSIRTGThreat.clear()
        self.processData("CSIRTG")

#End EmergingThreatsv2
