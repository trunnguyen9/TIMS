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

class SQLiteDataStore:

    def __init__(self):
        print ("Connecting to SQLite DB for storing IOCs..")
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