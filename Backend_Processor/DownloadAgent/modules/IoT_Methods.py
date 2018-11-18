# SimpleIOC
# Darrell Miller
# darrellrhodesmiller@gmail.com
#
# The following code outlines uniform functions that are intended
# to be accesible by all specific IoC modules.  Certain Functions
# may be overwritten by specific-resource modules


from pprint import pprint
from datetime import datetime
from queue import Queue
# from elasticsearch import Elasticsearch
from .DataStore_SQLite import SQLiteDataStore
import _sqlite3
import hashlib
import socket
# import elasticsearch
import urllib.request
import urllib.parse


import threading
import requests
from hashlib import md5
import json
from multiprocessing.dummy import Pool as ThreadPool
import multiprocessing
import time

class IoC_Methods:
    threatCounter = 0
    urlList = []
    urlQueue = Queue()

    recordedThreats = dict()  # where threats are stored to put uploaded to database
    multiThreadQueue = Queue()
    multiprocessingList = list()
    uri = ''  # Link to Location of Threats to be Extracted
    TIMSlog = dict()
    es = 0

    conn = 0
    cursor = 0
    testCounter = 0
    hostname = ""
    SQLiteDataStore = ""

    def __init__(self):
        # def __init__(self):
        print("--===================================--")
        self.hostname = socket.gethostname()
        self.TIMSlog['lineCount'] = 0
        self.TIMSlog['newCount'] = 0
        self.TIMSlog['dupeCount'] = 0
        self.TIMSlog['startTime'] = datetime.utcnow()
        print ("Start Time:", self.TIMSlog['startTime'])
        self.TIMSlog['endTime'] = ""
        self.TIMSlog['sqlEntries'] = 0
        self.TIMSlog['SQLErrorCount'] = 0
        self.TIMSlog['Error'] = None

        try:
            self.es = Elasticsearch([{'host': '173.253.201.243', 'port': 9200}])
        except Exception as ex :
            print ("ES ERROR:", ex)

    def pull(self,urlItem):
        x = urllib.request.urlopen(self.uri)
        results = x.read()
        results = results.decode("utf-8")
        return results

    def createMD5Key(self, keystring):
        m = hashlib.md5()
        m.update(keystring.encode('utf-8'))
        md5string = m.hexdigest()
        return md5string

    # endcreateMD5Key

    def addToDatabase(self,dbConn, dbCursor, allThreats):
        conn = dbConn
        threatCounter = 1
        totalThreats = len(allThreats)
        currentDateTime = datetime.utcnow()
        cursor = dbCursor

        #pprint (allThreats)

        for item in allThreats:
            self.TIMSlog['lineCount'] += 1
            #print (self.TIMSlog['lineCount'])
            try:
                cursor.execute("INSERT INTO RecordedThreatsDB VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               [allThreats[item]['tlp'],
                                allThreats[item]['lasttime'],
                                allThreats[item]['reporttime'],
                                allThreats[item]['icount'],
                                allThreats[item]['itype'],
                                allThreats[item]['indicator'],
                                allThreats[item]['cc'],
                                allThreats[item]['gps'],
                                allThreats[item]['asn'],
                                allThreats[item]['asn_desc'],
                                allThreats[item]['confidence'],
                                allThreats[item]['description'],
                                allThreats[item]['tags'],
                                allThreats[item]['rdata'],
                                allThreats[item]['provider'],
                                allThreats[item]['threatkey'],
                                str(currentDateTime),
                                allThreats[item]['enriched'],
                                ])
                try:
                    allThreats[item]['es_time']=datetime.utcnow()
                    #self.es.index(index='timsthreat_index', doc_type='timsthreat', id=allThreats[item]['reporttime'],
                    #              body=allThreats[item])
                except elasticsearch.ElasticsearchException as es1:
                    print("RT Error:" + es1)

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
                conn.commit()

    # end addToDataBase

    def writeLogToDB(self, dbConn, dbCursor, providerName):
        cursor = dbCursor

        self.TIMSlog['endTime'] = datetime.utcnow()
        print ("End Time:", self.TIMSlog['endTime'] )
        print(" - Total Entries:" + str(self.TIMSlog['lineCount']))
        print(" - New Entries:" + str(self.TIMSlog['newCount']))
        print(" - Duplicates:" + str(self.TIMSlog['dupeCount']))
        print(" -- Start Time:" + str(self.TIMSlog['startTime']))
        print(" -- End Time:" + str(self.TIMSlog['endTime']))
        print(" -- Total Time Spent:" + str(self.TIMSlog['endTime'] - self.TIMSlog['startTime']))
        self.TIMSlog['Provider']=providerName
        self.TIMSlog['host']=self.hostname
        timediff= (self.TIMSlog['endTime'] - self.TIMSlog['startTime'])

        self.TIMSlog['timeSpent'] = timediff.total_seconds()


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
        dbConn.commit()

        print("-- --  sending to ES  -- --")
        if (self.TIMSlog['newCount'] >0 ):
            print (self.TIMSlog['Provider'], " has new entries: ", self.TIMSlog['newCount'])
            try:
                self.es.index(index='timslog_index', doc_type='timslog', id=self.TIMSlog['startTime'], body=self.TIMSlog)
            except elasticsearch.ElasticsearchException as es1:
                print("TL Error:" + es1)

        self.TIMSlog['dupeCount'] = 0
        self.TIMSlog['newCount'] = 0
        self.TIMSlog['lineCount'] = 0

        # --==========================================--

    # end writeLogToDB

    # Multi-Threading Stuff
    def worker(self):
        # print("Worker Function:!")
        while not self.urlQueue.empty():
            itemToPull = self.urlQueue.get()
            print("Thread: :", itemToPull, "processing.. please wait.. ")
            self.pull(itemToPull)
    # end worker

    def multiThreader(self):
        # build queue for multiThreading
        for item in self.urlList:
            # print("Put:", item, " in Queue for Multi-Threading")
            self.urlQueue.put(item)

        threads = []
        intQueueCount = self.urlQueue.qsize()
        if (intQueueCount > 50):
            intQueueCount = 50

        # print("Queue Size:", intQueueCount)
        for i in range(intQueueCount):
            t = threading.Thread(target=self.worker)
            threads.append(t)

        for x in threads:
            x.start()

        for y in threads:
            y.join()