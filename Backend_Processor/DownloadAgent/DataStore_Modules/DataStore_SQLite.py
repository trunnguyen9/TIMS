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

from pprint import pprint
from datetime import datetime
import _sqlite3
# import FrontEnd_GUI
# import PySimpleGUI as sg

class SQLiteDataStore:

    threatLibrary = dict()
    sqlStringDict = dict()
    log = dict()
    errorLog = dict()
    conn = 0
    cursor = 0

    def __init__(self):
        print ("Building Network Connection and Connection Cursor:")
        self.conn = _sqlite3.connect('../../Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
        self.cursor=self.conn.cursor()
    # end constructor

    def getDBConn(self):
        return self.conn
    # end getDBConn

    def getDBCursor(self):
        return self.cursor
    # end getDBCursor

    def OLD_init(self, threatResults):
        # clearing variables and setting up the log counters
        # --===========================================--
        self.log['lineCount'] = 0
        self.log['newCount'] = 0
        self.log['dupeCount'] = 0
        self.log['startTime'] = datetime.now()
        self.log['endTime'] = ""
        self.log['sqlEntries'] = 0
        self.log['SQLErrorCount'] = 0
        self.threatLibrary = threatResults.copy()
        # --===========================================--
        print ("Connecting to SQLite DB for storing IOCs..")
    # end constructor

    def checkDBForDuplicate(self, threatkey, con):
        cursor = con.cursor()
        sqlString = "SELECT * FROM `RecordedThreatsDB` WHERE `threatKey` ="
        sqlString += "'" + threatkey + "'"
        cursor.execute(sqlString)
        msg = cursor.fetchone()
        self.log['lineCount'] += 1
        if (msg):
            self.log['dupeCount'] += 1
            return 1
        else:
            self.log['newCount'] += 1
            return 0
    # checkDBForDuplicate

    def insertRowIntoDB(self, sqlString,con):
        print (sqlString)
        cursor = con.cursor()
        cursor.execute(sqlString)
    # END insertRowIntoDB

    def processNewThreats(self):
        threatCounter = 1
        totalThreats = len(self.threatLibrary)
        currentDateTime = datetime.now()

        con = _sqlite3.connect('../../Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
        cursor = con.cursor()

        print ("--===================--")
        progressBarTicker = 0
        for item in self.threatLibrary:
            progressBarTicker +=1
            sg.EasyProgressMeter("Checking Database for Records",progressBarTicker,len(self.threatLibrary))
         #print (self.checkDBForDuplicate(self.threatLibrary[item]['threatkey'],con))
            if self.checkDBForDuplicate(self.threatLibrary[item]['threatkey'],con) == 0:
                print("[", threatCounter, "/", totalThreats, "]", "Checking Database for Record:", item, ": New Threat")
                cursor.execute("INSERT INTO RecordedThreatsDB VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               [self.threatLibrary[item]['tlp'],
                                self.threatLibrary[item]['lasttime'],
                                self.threatLibrary[item]['reporttime'],
                                self.threatLibrary[item]['icount'],
                                self.threatLibrary[item]['itype'],
                                self.threatLibrary[item]['indicator'],
                                self.threatLibrary[item]['cc'],
                                self.threatLibrary[item]['gps'],
                                self.threatLibrary[item]['asn'],
                                self.threatLibrary[item]['asn_desc'],
                                self.threatLibrary[item]['confidence'],
                                self.threatLibrary[item]['description'],
                                self.threatLibrary[item]['tags'],
                                self.threatLibrary[item]['rdata'],
                                self.threatLibrary[item]['provider'],
                                self.threatLibrary[item]['threatkey'],
                                str(currentDateTime),
                                self.threatLibrary[item]['enriched'],
                                ])
                if threatCounter%5000==0: #saves db every 5000 records
                    con.commit()
            else:
                print("[", threatCounter, "/", totalThreats, "] Checking Database for Record:", item,
                      ": Already in Database")
            threatCounter += 1
        con.commit()
        con.close()
        print ("--===================--")
    # end processNewThreats

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

    def recordStats(self):

        self.log['endTime']= datetime.now()
        print ("-- ============================ --")
        print("Total Entries:" + str( self.log['lineCount']))
        print ("New Entries:" + str( self.log['newCount']))
        print("Duplicates:" + str( self.log['dupeCount']))
        print("Start Time:" + str( self.log['startTime']))
        print("End Time:" + str( self.log['endTime']) )
        print ("Total Time Spent:" + str (self.log['endTime'] - self.log['startTime']))

        sg.Popup("Import Finished",
                 "Total Entries: " + str( self.log['lineCount']),
                 "New Entries: " + str( self.log['newCount']),
                 "Duplicates: " + str(self.log['dupeCount']),
                 "Start Time:" + str(self.log['startTime']),
                 "End Time:" + str(self.log['endTime']),
                 "Total Time Spent:" + str(self.log['endTime'] - self.log['startTime']))



        con = _sqlite3.connect('../../Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
        cursor = con.cursor()
        cursor.execute("INSERT INTO ThreatStatsDB VALUES (?,?,?,?,?,?)",
                       [self.log['lineCount'],
                        self.log['newCount'],
                        self.log['dupeCount'],
                        str(self.log['startTime']),
                        str(self.log['endTime']),
                        str((self.log['endTime'] - self.log['startTime']))
                        ])
        print ("committing to Logging DB")
        con.commit()
    # END show stats

#end SQLiteDataStore

