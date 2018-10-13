# SimpleIOC
# Darrell Miller
# darrellrhodesmiller@gmail.com
#
# The following code outlines uniform functions that are intended
# to be accesible by all specific IoC modules.  Certain Functions
# may be overwritten by specific-resource modules

import urllib.request
import urllib.parse
import json
from pprint import pprint
from datetime import datetime
import requests
from queue import Queue
import threading
import _sqlite3

import hashlib
from hashlib import md5

from multiprocessing.dummy import Pool as ThreadPool
import multiprocessing
import socket
import time
import elasticsearch


class IoC_Methods:
    threatCounter = 0
    TotalThreats = 0  # total threats downloaded
    NewThreats = 0  # new threats not in database
    DuplicateThreats = 0  # threats downloaded that were already in database

    recordedThreats = dict()  # where threats are stored to put uploaded to database
    multiThreadQueue = Queue()
    multiprocessingList = list()
    uri = ''  # Link to Location of Threats to be Extracted
    TIMSlog = dict()

    conn = 0
    cursor = 0
    testCounter = 0
    hostname = ""

    def __init__(self, conn):
        # def __init__(self):
        print("--===================================--")
        self.hostname = socket.gethostname()
        self.conn = conn
        self.cursor = self.conn.cursor()
        self.TIMSlog['lineCount'] = 0
        self.TIMSlog['newCount'] = 0
        self.TIMSlog['dupeCount'] = 0
        self.TIMSlog['startTime'] = datetime.now()
        self.TIMSlog['endTime'] = ""
        self.TIMSlog['sqlEntries'] = 0
        self.TIMSlog['SQLErrorCount'] = 0
        self.TIMSlog['Error'] = None

    def pull(self):
        # I think it might be worth making the URI an attribute of the class - Doug
        x = urllib.request.urlopen(self.uri)
        results = x.read()
        results = results.decode("utf-8")
        return results

    def showThreats(self):
        pprint(self.recordedThreats)

    # end show Threats

    def getThreats(self):
        return self.recordedThreats.copy()

    def createMD5Key(self, keystring):
        m = hashlib.md5()
        m.update(keystring.encode('utf-8'))
        md5string = m.hexdigest()
        return md5string

    # endcreateMD5Key

    def processData(self, providerName):
        self.makeList()
        self.addToDatabase2()
        # self.multiThreadedAdd()
        self.writeLogToDB(providerName)

    # end makeQueue

    def addToDatabase2(self):
        threatCounter = 1
        totalThreats = len(self.recordedThreats)
        currentDateTime = datetime.now()
        cursor = self.conn.cursor()

        for item in self.recordedThreats:
            self.TIMSlog['lineCount'] += 1
            try:
                cursor.execute("INSERT INTO RecordedThreatsDB VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               [self.recordedThreats[item]['tlp'],
                                self.recordedThreats[item]['lasttime'],
                                self.recordedThreats[item]['reporttime'],
                                self.recordedThreats[item]['icount'],
                                self.recordedThreats[item]['itype'],
                                self.recordedThreats[item]['indicator'],
                                self.recordedThreats[item]['cc'],
                                self.recordedThreats[item]['gps'],
                                self.recordedThreats[item]['asn'],
                                self.recordedThreats[item]['asn_desc'],
                                self.recordedThreats[item]['confidence'],
                                self.recordedThreats[item]['description'],
                                self.recordedThreats[item]['tags'],
                                self.recordedThreats[item]['rdata'],
                                self.recordedThreats[item]['provider'],
                                self.recordedThreats[item]['threatkey'],
                                str(currentDateTime),
                                self.recordedThreats[item]['enriched'],
                                ])
                if threatCounter % 5000 == 0:  # saves db every 5000 records
                    self.conn.commit()
                self.TIMSlog['newCount'] += 1
                #print("[", self.TIMSlog['lineCount'], "/", totalThreats, "] : Added to Database - NEW")
            except _sqlite3.Error as e:
                #print("[", self.TIMSlog['lineCount'], "/", totalThreats, "] : Not Added to Database - Duplicate")
                self.TIMSlog['dupeCount'] += 1
            except Exception as e:
                print("Exception in _query: %s" % e)
            finally:
                self.conn.commit()
    # end addToDataBase

    def writeLogToDB(self, providerName):
        cursor = self.conn.cursor()

        self.TIMSlog['endTime'] = datetime.now()
        print(" - Total Entries:" + str(self.TIMSlog['lineCount']))
        print(" - New Entries:" + str(self.TIMSlog['newCount']))
        print(" - Duplicates:" + str(self.TIMSlog['dupeCount']))
        print(" -- Start Time:" + str(self.TIMSlog['startTime']))
        print(" -- End Time:" + str(self.TIMSlog['endTime']))
        print(" -- Total Time Spent:" + str(self.TIMSlog['endTime'] - self.TIMSlog['startTime']))

        cursor.execute("INSERT INTO ThreatStatsDB VALUES (?,?,?,?,?,?,?,?)",
                       [self.TIMSlog['lineCount'],
                        self.TIMSlog['newCount'],
                        self.TIMSlog['dupeCount'],
                        str(self.TIMSlog['startTime']),
                        str(self.TIMSlog['endTime']),
                        str((self.TIMSlog['endTime'] - self.TIMSlog['startTime'])),
                        providerName,
                        self.hostname
                        ])
        self.conn.commit()


        self.TIMSlog['dupeCount'] = 0
        self.TIMSlog['newCount'] = 0
        self.TIMSlog['lineCount'] = 0

    # end writeLogToDB

    def makeList(self):

        for item in self.recordedThreats:
            self.multiprocessingList.append(self.recordedThreats[item])
        self.TotalThreats = len(self.multiprocessingList)
    # end makeList