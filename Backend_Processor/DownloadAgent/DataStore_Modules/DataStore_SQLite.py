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

class SQLiteDataStore:

    threatLibrary = dict()
    sqlStringDict = dict()
    log = dict()
    errorLog = dict()

    def __init__(self, threatResults):
    #def __init__(self):
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

    def checkDBForDuplicate(self, key, con):
        cursor = con.cursor()
        sqlString = "SELECT * FROM `RecordedThreatsDB` WHERE `indicator` ="
        sqlString += "'" + key + "'"
        cursor.execute(sqlString)
        msg = cursor.fetchone()
        if (cursor.rowcount) > 0:
            self.log['dupeCount'] += 1
            return 1
        else:
            self.log['newCount'] += 1
            return 0
    # checkDBForDuplicate

    def buildSQLInsertString(self, threatInfo):

        sqlString = "INSERT into RecordedThreatsDB ("
        sqlString += "`tlp`,"
        sqlString += "`lastTime`,"
        sqlString += "`reportTime`,"
        sqlString += "`count`,"
        sqlString += "`iType`,"
        sqlString += "`indicator`,"
        sqlString += "`cc`,"
        sqlString += "`gps`,"
        sqlString += "`asn`,"
        sqlString += "`asn_desc`,"
        sqlString += "`confidence`,"
        sqlString += "`description`,"
        sqlString += "`tags`,"
        sqlString += "`rData`,"
        sqlString += "`provider`,"
        sqlString += "`threatKey`,"
        sqlString += "`entryTime`,"
        sqlString += "`enriched`)"

        sqlString += " VALUES ('"
        sqlString += threatInfo['tlp'] + "','"
        sqlString += threatInfo['lasttime'] + "','"
        sqlString += threatInfo['reporttime'] + "','"
        sqlString += str(threatInfo['count']) + "','"
        sqlString += threatInfo['itype'] + "','"
        sqlString += threatInfo['indicator'] + "','"
        sqlString += threatInfo['cc'] + "','"
        sqlString += "GPS long,lat" + "','"
        sqlString += threatInfo['asn'] + "','"
        sqlString += threatInfo['asn_desc'] + "','"
        sqlString += str(threatInfo['confidence']) + "','"
        sqlString += threatInfo['description'] + "','"
        sqlString += threatInfo['tags'] + "','"
        sqlString += threatInfo['rdata'] + "','"
        sqlString += threatInfo['provider'] + "','"

        sqlString += threatInfo['key'] + "','"

        currentDateTime = datetime.now()
        sqlString += str(currentDateTime) + "','"
        sqlString += "FALSE" + "')"
        return sqlString

    # END BuildSQLInsertString

    def insertRowIntoDB(self, sqlString,con):
        print (sqlString)
        cursor = con.cursor()
        #cursor.execute(sqlString)
    # END insertRowIntoDB

    def processNewThreats(self):
        threatCounter = 1
        totalThreats = len(self.threatLibrary)

        con = _sqlite3.connect('../../Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
        cursor = con.cursor()
        print ("--===================--")
        for item in self.threatLibrary:
            if self.checkDBForDuplicate(item, con) == 0:
                print("[", threatCounter, "/", totalThreats, "]", "Checking Database for Record:", item, ": New Threat")
                self.insertRowIntoDB(self.buildSQLInsertString(self.threatLibrary[item]), con)
                if threatCounter % 500 == 0:  # saves db every 500 records
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

        con = _sqlite3.connect('../../Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
        cursor = con.cursor()
        print(str(datetime.now()))
        cursor.execute("SELECT * FROM RecordedThreatsDB;")
        print(cursor.fetchall());

        print("## ALL THREATS!! ##")
        # pprint (self.threatLibrary)
        print("## Done ## ")
    #end showDataInThreatDB

#end SQLiteDataStore

