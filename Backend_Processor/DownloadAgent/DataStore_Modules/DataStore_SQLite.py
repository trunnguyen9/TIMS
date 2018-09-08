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

    def __init__(self):
        print ("Connecting to SQLite DB for storing IOCs..")
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
    #end constructor

    def addDataToStore(self, newDataDictionary):
       print ("someday this will work :)")
    #end addDataToStore

    def showDataStore(self):
        pprint(self.allThreats)
    #end showDataStore

    def getDataStore(self):
        return self.allThreats.copy()
    #end getDataStore
#end SQLiteDataStore