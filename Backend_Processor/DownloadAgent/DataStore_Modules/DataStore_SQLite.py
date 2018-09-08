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

        '''
        con = _sqlite3.connect('../../Threats.sqlite',detect_types=_sqlite3.PARSE_DECLTYPES)
        cursor = con.cursor()

        datetimevalue = datetime.now()

        print (datetimevalue.now())
        cursor.execute("SELECT * FROM ThreatLoggerDB;")
        cursor.execute('insert into ThreatLoggerDB values (?,?,?)', ['12','blah', str(datetimevalue)] )
        con.commit()
        cursor = con.cursor()

        print(cursor.fetchall())

        noThreats = 11
        notes = "blah blah blah"
        indexKey= datetime

        #cursor.execute("INSERT INTO threatLogger(noThreats,Notes,indexKey) values ("'11','blahblahblah',datetime"))
        con.close()
        '''
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

'''
# SimpleIOC
# Darrell Miller
# darrellrhodesmiller@gmail.com

# DataStore_MySQL
# Methods for communicating with a MYSQL Database

import datetime
import hashlib

#import mysql.connector
#from mysql.connector import errorcode

import json
from pprint import pprint

    def processNewThreats(self):
        threatCounter=1
        totalThreats=len(self.threatLibrary)
        cnx = mysql.connector.connect(user='otcuser', password='Monday@1', host='localhost', database='simpleIOC')
	#cnx = mysql.connector.connect(user='otcuser', password='Monday@1', host='68.11.224.59', port=10888, database='simpleIOC')
        for item in self.threatLibrary:
            if self.checkDBForDuplicate(item,cnx) == 0:
                print("[", threatCounter, "/", totalThreats, "]", "Checking Database for Record:", item, ": New Threat")
                self.insertRowIntoDB(self.buildSQLInsertString(self.threatLibrary[item]),cnx)
                if threatCounter%500==0: #saves db every 500 records
                    cnx.commit()
            else:
                print("[",threatCounter,"/",totalThreats,"] Checking Database for Record:", item, ": Already in Database")
            threatCounter+=1
        cnx.commit()
        cnx.close()
    #end processNewThreats

    def buildSQLInsertString(self, threatInfo):

        sqlString = "INSERT into RecordedThreats ("
        sqlString += "`tlp`,"
        sqlString += "`lasttime`,"
        sqlString += "`reporttime`,"
        sqlString += "`count`,"
        sqlString += "`itype`,"
        sqlString += "`indicator`,"
        sqlString += "`cc`,"
        sqlString += "`asn`,"
        sqlString += "`asn_desc`,"
        sqlString += "`confidence`,"
        sqlString += "`description`,"
        sqlString += "`tags`,"
        sqlString += "`rdata`,"
        sqlString += "`provider`,"
        sqlString += "`threatkey`,"
        sqlString += "`entrytime`)"

        sqlString += " VALUES ('"
        sqlString += threatInfo['tlp'] + "','"
        sqlString += threatInfo['lasttime'] + "','"
        sqlString += threatInfo['reporttime'] + "','"
        sqlString += str(threatInfo['count']) + "','"
        sqlString += threatInfo['itype'] + "','"
        sqlString += threatInfo['indicator'] + "','"
        sqlString += threatInfo['cc'] + "','"
        sqlString += threatInfo['asn'] + "','"
        sqlString += threatInfo['asn_desc'] + "','"
        sqlString += str(threatInfo['confidence']) + "','"
        sqlString += threatInfo['description'] + "','"
        sqlString += threatInfo['tags'] + "','"
        sqlString += threatInfo['rdata'] + "','"
        sqlString += threatInfo['provider'] + "','"

        sqlString += threatInfo['key'] + "','"
        currentDateTime = datetime.datetime.now()
        sqlString += str(currentDateTime) + "')"
        return sqlString
    # END BuildSQLInsertString

    def insertRowIntoDB(self, sqlString,cnx):
        try:
            cursor = cnx.cursor()
            cursor.execute(sqlString)
        except mysql.connector.Error as err:
            errorInfo=dict()
            errorInfo['SQLString']=sqlString
            errorInfo['ErrorInfo']=err
            self.errorLog[self.log['SQLErrorCount']]=errorInfo
            self.log['SQLErrorCount']+=1
    # END insertRowIntoDB

    def loadDB(self):
        self.log['sqlEntries']=len(self.sqlStringDict)
        insertCount=1

        cnx = mysql.connector.connect(user='otcuser', password='Monday@1', host='localhost', database='simpleIOC')
	#cnx = mysql.connector.connect(user='otcuser', password='Monday@1', host='68.11.224.59', port=10888, database='simpleIOC')

        for sqlItem in self.sqlStringDict:
            #print ("Inserting record: [", insertCount, "/", self.log['sqlEntries'],"]")
            self.insertRowIntoDB(self.sqlStringDict[sqlItem], cnx)
            insertCount+=1
        cnx.commit()  # move this outside
        cnx.close()
    # END loadDB


    def showSQLStrings(self):
        pprint(self.sqlStringDict)
    # END showSQLStrings

    def stopClock(self):
        self.log['endTime'] = datetime.datetime.now()
        self.log['totalTime'] = str(self.log['endTime'] - self.log['startTime'])
    # END stopclock

    def showStats(self):
        self.stopClock()
        print("Total Lines Processed: ", self.log['lineCount'])
        print("New Unique Signatures Added to Database: ", self.log['newCount'])
        print("Duplicate Signatures NOT added to Database:", self.log['dupeCount'])
        print("Total Time to Process: ", str(self.log['totalTime']))
        self.saveErrorLog()
    # END showStats

    def saveErrorLog(self):
        currenttime=(str(datetime.datetime.now()))
        strTime="---------- BEGIN:"+ currenttime + "  ----------\n"

        TotalLines="Total Lines Processed: " + str(self.log['lineCount']) +"\n"
        TotalUnique="New Unique Signatures Added to Database: " + str(self.log['newCount']) + "\n"
        TotalDuplicates="Duplicate Signatures NOT added to Database:" + str(self.log['dupeCount']) + "\n"
        TotalTime="Total Time to Process: " + str(self.log['totalTime']) + "\n"

        errorFile=open("/home/dmuser/FinalProject/logs/errorLog.log","a")
        errorFile.write(strTime)
        errorFile.write(TotalLines)
        errorFile.write(TotalUnique)
        errorFile.write(TotalDuplicates)
        errorFile.write(TotalTime)
        errorFile.write("\n")
        for x in self.errorLog:
            strToWrite="--" + str(self.errorLog[x]['ErrorInfo']) + "\n"
            errorFile.write(strToWrite)
            strToWrite="--" + self.errorLog[x]['SQLString'] + "\n"
            errorFile.write(strToWrite)
        errorFile.write("\n")
        errorFile.close()
#End dataStore_MySQL

class dataStore_MySQL_Logger:
    def __init__(self):
        print ("Starting MySql Logger:")
    # END __init__

    def writeToLog(self, strFeedName,intThreatNumber, strNotes):
        cnx = mysql.connector.connect(user='otcuser', password='Monday@1', host='localhost', database='simpleIOC')
        sqlString=self.buildLogSQLString(strFeedName,intThreatNumber,strNotes)
        cursor = cnx.cursor()
        cursor.execute(sqlString)
        #print ("SQL:", sqlString)
        cnx.commit()  # move this outside
        cnx.close()
    #end writeToLog

    def buildLogSQLString(self,strFeedName,IntThreatNumber,strNotes):
        strSQLString="INSERT INTO `threatLogger` (`Provider`, `No_of_Threats`, `Notes`, `indexKey`) VALUES ('"
        strSQLString+=strFeedName+"','"
        strSQLString+=str(IntThreatNumber)+"','"
        strSQLString+=strNotes+"',CURRENT_TIMESTAMP)"
        #print (strSQLString)
        return strSQLString
    #end buildLogSqlString

#end class dataStore_MySql_Logger
'''