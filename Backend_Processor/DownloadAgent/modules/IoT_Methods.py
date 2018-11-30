# SimpleIOC
# Darrell Miller
# darrellrhodesmiller@gmail.com
#
# The following code outlines uniform functions that are intended
# to be accesible by all specific IoC modules.  Certain Functions
# may be overwritten by specific-resource modules

# import necessary libraries
from datetime import datetime
from queue import Queue
from elasticsearch import Elasticsearch
import _sqlite3
import hashlib
import socket
import elasticsearch
import urllib.request
import urllib.parse
import sys
import threading
import time


# Main Base Class for all the Threat Libraries

class IoC_Methods:
    threatCounter = 0  # counts the number threats in datafeed
    urlList = []  # some feeds have multiple URLS, this is a list of those URLS to pull from
    urlQueue = Queue()  # queue of URL's to pull

    recordedThreats = dict()  # where threats are stored to put uploaded to database
    # multiThreadQueue = Queue()      # create a queue for multi-threader to pull feeds
    # multiprocessingList = list()    # not sure if i still use this
    uri = ''  # Link to Location of Threats to be Extracted
    TIMSlog = dict()  # basic log for actions taken
    es = 0  # basic elastic search object
    textURI = ""

    conn = 0  # sqlite database connection
    cursor = 0  # sqlite cursor
    # testCounter = 0
    hostname = ""  # hostname of PC running scripts
    SQLiteDataStore = ""  # sqlite datastore

    def __init__(self):

        self.hostname = socket.gethostname()  # gets hostname of PC running the script

        # sets initial values for Log
        self.TIMSlog['lineCount'] = 0
        self.TIMSlog['newCount'] = 0
        self.TIMSlog['dupeCount'] = 0
        self.TIMSlog['startTime'] = datetime.utcnow()
        self.TIMSlog['endTime'] = ""
        self.TIMSlog['sqlEntries'] = 0
        self.TIMSlog['SQLErrorCount'] = 0
        self.TIMSlog['Error'] = None

        # connects to elastic search / big data server
        try:
            self.es = Elasticsearch([{'host': '173.253.201.243', 'port': 9200}])
        except Exception as ex :
            print ("ES ERROR:", ex)

    # base pull f(x) will be over written by each custom feed method
    def pull(self,urlItem):
        x = urllib.request.urlopen(self.uri)
        results = x.read()
        results = results.decode("utf-8")
        return results

    # used to create MD5 hash for primary key of database from indicator of threat
    def createMD5Key(self, keystring):
        m = hashlib.md5()
        m.update(keystring.encode('utf-8'))
        md5string = m.hexdigest()
        return md5string
    # endcreateMD5Key

    # add item to database
    def addToDatabase(self,dbConn, dbCursor, allThreats):
        conn = dbConn
        threatCounter = 1
        currentDateTime = datetime.utcnow()
        cursor = dbCursor

        # print("Number of Threats::" + str(len(allThreats)))

        for item in allThreats:
            self.TIMSlog['lineCount'] += 1
            str_printline = allThreats[item]['provider'] + ":" + str(
                self.TIMSlog['lineCount']) + " --- Indicator : " + str(allThreats[item]['indicator'])
            self.print_line(str_printline)

            try:
                # database insert
                cursor.execute("INSERT INTO RecordedThreatsDB VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                                allThreats[item]['enriched'],  # fix this, this is a hack of a solution
                                allThreats[item]['enriched'],  # fix this, this is a hack of a solution
                                allThreats[item]['enriched'],  # fix this, this is a hack of a solution
                                allThreats[item]['enriched'],  # fix this, this is a hack of a solution
                                allThreats[item]['enriched']  # fix this, this is a hack of a solution
                                ])

                # commit/save to database every 500 records (in case of a crash you dont have to start all the way over)
                if threatCounter % 500 == 0:  # saves db every 5000 records
                    self.conn.commit()
                # counts new threats/indicators
                self.TIMSlog['newCount'] += 1

            except _sqlite3.Error as e:
                # counts duplicates, records already in the database dont need to be added again
                self.TIMSlog['dupeCount'] += 1
            except _sqlite3.OperationalError as e:
                # if database locked, wait 1 sec and try again
                print("DB wait, collision!")
                time.sleep(1)
                self.conn.commit()
            except Exception as e:
                print("Exception in _query: %s" % e)
            finally:
                # save to database
                conn.commit()
        print(" ")
    # end addToDataBase

    # basic log of activities
    def writeLogToDB(self, dbConn, dbCursor, providerName):
        cursor = dbCursor

        self.TIMSlog['endTime'] = datetime.utcnow()
        # print ("End Time:", self.TIMSlog['endTime'] )
        # print(" - Total Entries:" + str(self.TIMSlog['lineCount']))
        # print(" - New Entries:" + str(self.TIMSlog['newCount']))
        # print(" - Duplicates:" + str(self.TIMSlog['dupeCount']))
        # print(" -- Start Time:" + str(self.TIMSlog['startTime']))
        # print(" -- End Time:" + str(self.TIMSlog['endTime']))
        # print(" -- Total Time Spent:" + str(self.TIMSlog['endTime'] - self.TIMSlog['startTime']))
        self.TIMSlog['Provider']=providerName
        self.TIMSlog['host']=self.hostname
        timediff= (self.TIMSlog['endTime'] - self.TIMSlog['startTime'])

        self.TIMSlog['timeSpent'] = timediff.total_seconds()

        # save log info to log database
        try:
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
        except _sqlite3.OperationalError as e:  # if database is locked, wait a second and try again.
            time.sleep(1)
            dbConn.commit()

        # print("-- --  sending to ES  -- --")
        if (self.TIMSlog['newCount'] >0 ):
            # print (self.TIMSlog['Provider'], " has new entries: ", self.TIMSlog['newCount'])
            try:
                self.es.index(index='timslog_index', doc_type='timslog', id=self.TIMSlog['startTime'], body=self.TIMSlog)
            except elasticsearch.ElasticsearchException as es1:
                print("TL Error:" + es1)
        self.TIMSlog['dupeCount'] = 0
        self.TIMSlog['newCount'] = 0
        self.TIMSlog['lineCount'] = 0
    # end writeLogToDB

    # Multi-Threading Stuff
    def worker(self):
        # print("Worker Function:!")
        while not self.urlQueue.empty():
            itemToPull = self.urlQueue.get()
            # print("Thread: :", itemToPull, "processing.. please wait.. ")
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

    def print_line(self, string):
        sys.stdout.flush()
        sys.stdout.write('\r' + string + " -- ")
