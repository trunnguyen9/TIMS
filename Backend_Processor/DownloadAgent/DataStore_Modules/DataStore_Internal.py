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

class interalDataStore:
    allThreats=dict()

    def __init__(self):
        print ("Building datastructure for storing IOCs..")
    #end constructor

    def addDataToStore(self, newDataDictionary):
        for item in newDataDictionary:
            if newDataDictionary[item]['indicator'] in self.allThreats.keys():
                if type(self.allThreats[newDataDictionary[item]['indicator']]['icount'])==int:
                    self.allThreats[newDataDictionary[item]['indicator']]['icount']+=1
                else:
                    print ("WTF!!!!", type(self.allThreats[newDataDictionary[item]['indicator']]['icount']))
                print("Duplicate, adding to count of previous entry")
                print("COUNT::", self.allThreats[newDataDictionary[item]['indicator']]['icount'])
            else:
                self.allThreats[newDataDictionary[item]['indicator']]=newDataDictionary[item]
    #end addDataToStore

    def showDataStore(self):
        pprint(self.allThreats)
    #end showDataStore

    def getDataStore(self):
        return self.allThreats.copy()
    #end getDataStore
#end internalDataStore
