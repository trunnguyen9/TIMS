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

class IoC_Methods:
    threatCounter = 0
    TotalThreats = 0  # total threats downloaded
    NewThreats = 0  # new threats not in database
    DuplicateThreats = 0  # threats downloaded that were already in database

    recordedThreats = dict()  # where threats are stored to put uploaded to database
    multiThreadQueue = Queue()
    multiprocessingList = list()
    uri = ''  # Link to Location of Threats to be Extracted
    log = dict()

    conn = 0
    cursor=0
    testCounter = 0
    hostname = ""

    def __init__(self, conn):
        print('Generic IoC Constructor')
        self.hostname=socket.gethostname()
        self.conn=conn
        self.cursor=self.conn.cursor()
        self.log['lineCount'] = 0
        self.log['newCount'] = 0
        self.log['dupeCount'] = 0
        self.log['startTime'] = datetime.now()
        self.log['endTime'] = ""
        self.log['sqlEntries'] = 0
        self.log['SQLErrorCount'] = 0


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

    def checkDBForDuplicate(self, threatkey, con):
        dbConn = _sqlite3.connect('../../Threats.sqlite', check_same_thread=False, isolation_level=None)
        dbCursor = dbConn.cursor()

        #cursor = self.cursor
        sqlString = "SELECT * FROM `RecordedThreatsDB` WHERE `threatKey` ="
        sqlString += "'" + threatkey + "'"
        dbCursor.execute(sqlString)
        msg = dbCursor.fetchone()
        self.log['lineCount'] += 1
        if (msg):
            self.log['dupeCount'] += 1
            return 1
        else:
            self.log['newCount'] += 1
            return 0
        dbConn.close()
    # checkDBForDuplicate

    def processData(self, providerName):
        #self.addToDatabase()
        self.makeList()
        self.multiThreadedAdd()
        self.writeLogToDB(providerName)
    # end makeQueue

    def addToDatabase(self):
        threatCounter = 1
        totalThreats = len(self.recordedThreats)
        currentDateTime = datetime.now()

        con = self.conn
        cursor=con.cursor()

        print("--===================--")
        progressBarTicker = 0
        for item in self.recordedThreats:
            progressBarTicker += 1
            if self.checkDBForDuplicate(self.recordedThreats[item]['threatkey'], con) == 0:
                print("[", threatCounter, "/", totalThreats, "]", "Checking Database for Record:", item, ": New Threat")
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
                    con.commit()
            else:
                print("[", threatCounter, "/", totalThreats, "] Checking Database for Record:", item,
                      ": Already in Database")
            threatCounter += 1
        con.commit()
        print("--===================--")
    # end addToDataBase

    def writeLogToDB(self, providerName):
        cursor = self.conn.cursor()

        self.log['endTime'] = datetime.now()
        print("-- ============================ --")
        print("Total Entries:" + str(self.log['lineCount']))
        print("New Entries:" + str(self.log['newCount']))
        print("Duplicates:" + str(self.log['dupeCount']))
        print("Start Time:" + str(self.log['startTime']))
        print("End Time:" + str(self.log['endTime']))
        print("Total Time Spent:" + str(self.log['endTime'] - self.log['startTime']))

        cursor.execute("INSERT INTO ThreatStatsDB VALUES (?,?,?,?,?,?,?,?)",
                       [self.log['lineCount'],
                        self.log['newCount'],
                        self.log['dupeCount'],
                        str(self.log['startTime']),
                        str(self.log['endTime']),
                        str((self.log['endTime'] - self.log['startTime'])),
                        providerName,
                        self.hostname
                        ])
        print("committing to Logging DB")
        self.conn.commit()

    # end writeLogToDB

    def multiThreadedAdd(self):
        lock = multiprocessing.dummy.Lock()
        pool = ThreadPool(8)
        pool.map(self.worker, self.multiprocessingList)
        pool.close()
        pool.join()
        print ("test")
    # end multiThreadAdd

    def worker(self,d):
        self.testCounter+=1
        dbConn = _sqlite3.connect('../../Threats.sqlite', check_same_thread=False, isolation_level = None)
        dbCursor = dbConn.cursor()
        if self.checkDBForDuplicate(d['threatkey'], dbConn) == 0:
            dbCursor.execute("INSERT INTO RecordedThreatsDB VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           [d['tlp'],
                            d['lasttime'],
                            d['reporttime'],
                            d['icount'],
                            d['itype'],
                            d['indicator'],
                            d['cc'],
                            d['gps'],
                            d['asn'],
                            d['asn_desc'],
                            d['confidence'],
                            d['description'],
                            d['tags'],
                            d['rdata'],
                            d['provider'],
                            d['threatkey'],
                            str(datetime.now()),
                            d['enriched'],
                            ])
            print("[" + str(self.testCounter) + "/" + str(self.TotalThreats) + "Checking Database for Record:", d['indicator'],": NEW!!! NEW !!! NEW!! ")
        else:
            print("[" + str(self.testCounter) + "/" + str(self.TotalThreats) + " : Checking Database for Record:", d['indicator'], ": Already in Database")
        dbConn.commit()
        dbConn.close()
    # end worker

    def makeList(self):

        for item in self.recordedThreats:
            self.multiprocessingList.append(self.recordedThreats[item])
        #pprint (self.multiprocessingList)
        self.TotalThreats=len(self.multiprocessingList)
    #end makeList