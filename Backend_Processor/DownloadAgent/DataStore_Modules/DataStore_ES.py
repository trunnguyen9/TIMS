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

class ES_DataStore:
    ES_Server = "173.253.201.212" #Temp ES Server

    def __init__(self):
        print ("Building Elastic DataStore datastructure for storing IOCs..")
    #end constructor

    def addDataToStore(self, newDataDictionary):
        print ("Add to ES Server")
    #end addDataToStore

#end internalDataStore
