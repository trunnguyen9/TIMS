# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# simple methods used for internal data stucture/database
# used as internal datastore to consolidate all data from all sources

from datetime import datetime
import _sqlite3
from elasticsearch import Elasticsearch
import requests
import json


class SQLiteDataStore:

    threatLibrary = dict()
    sqlStringDict = dict()
    log = dict()
    errorLog = dict()
    conn = 0
    cursor = 0
    es = 0

    def __init__(self):
        #print ("Building Network Connection and Connection Cursor:")
        self.conn = _sqlite3.connect('../../Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
        #self.conn = _sqlite3.connect('Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
        self.cursor=self.conn.cursor()
        self.es = Elasticsearch([{'host':'173.253.201.212', 'port':9200}])

    # end constructor

    def getDBConn(self):
        return self.conn
    # end getDBConn

    def getDBCursor(self):
        return self.cursor
    # end getDBCursor


    def showDataInThreatDB(self):
        threatCounter = 1
        totalThreats = len(self.threatLibrary)

        con = _sqlite3.connect('../../Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        cursor = con.cursor()
        print(str(datetime.now()))
        cursor.execute("SELECT * FROM RecordedThreatsDB;")
        print(cursor.fetchall());

        print("## ALL THREATS!! ##")
        # pprint (self.threatLibrary)
        print("## Done ## ")
    #end showDataInThreatDB

#end SQLiteDataStore

