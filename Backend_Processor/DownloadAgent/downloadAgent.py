# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018!
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# This application will pull IOC (indicators of compromise) threat information from multiple sources then
# consolidate those sources into a database. Another application will then pull that information from the database
# and turn it into a form a firewall or IDS system can use.
# list of open threat feeds:
# - http://www.covert.io/threat-intelligence/
# - https://github.com/mlsecproject/combine/wiki/Threat-Intelligence-Feeds-Gathered-by-Combine
# This is the "hunter/gatherer" of this system. It will go through multiple sites and pull the information
# --====================================================--
#
#
# --====================================================--

# --====================================================--
# Import Necessary Libraries
# --====================================================--

from datetime import datetime
import modules
from threading import Thread
from queue import Queue
import json

from pprint import pprint
import time


# __MAIN__

# create SQLite DB Connection
#SQLiteDataStore = DataStore_Modules.DataStore_SQLite.SQLiteDataStore()

# create main DataStore for all threat information
# threatDataStore = DataStore_Modules.DataStore_Internal.interalDataStore()

if __name__ == '__main__':
    # create a time object to obtain current time
    todayDateTime = datetime.now()
    sourceList =[]


    try:
        while 1:
            objQueue = Queue()

            with open('config.json', 'r') as configFile:
                data = json.load(configFile)

            pprint (data)

            hourInterval = int(data['time'])
            currentHour = datetime.utcnow().hour
            # for testing
            # hourInterval=1
            print ("currentHour", currentHour,"interval:",data['time'],"mod:", (currentHour % hourInterval))

            if currentHour % hourInterval ==0 :
                print ("its the right time to process!: processing!!!")
                startTime= datetime.utcnow()

                pprint(data)

                for item in data['feedSources']:
                    sourceItem = item['name']+":"+str(item['selected'])
                    sourceList.append(sourceItem)

                if "NetLab360:True" in sourceList:
                    NetLabs360_Gatherer = modules.IoC_NetLabs360()
                    objQueue.put(NetLabs360_Gatherer)

                if "AlienVault:True" in sourceList:
                    AlienVault_Gatherer = modules.IoC_AlienVault()
                    objQueue.put(AlienVault_Gatherer)

                    #just temp until bug fixed:
                    NetLabs360_Gatherer = modules.IoC_NetLabs360()
                    objQueue.put(NetLabs360_Gatherer)

                if "Emerging:True" in sourceList:
                    EmergingThreats_gatherer = modules.IoC_EmergingThreats()
                    objQueue.put(EmergingThreats_gatherer)
                if "Feodotracker:True" in sourceList:
                    FedoTracker_Gatherer = modules.IoC_Feodotracker()
                    objQueue.put(FedoTracker_Gatherer)
                if "NoThink:True" in sourceList:
                    NoThink_Gatherer = modules.IoC_NoThink()
                    objQueue.put(NoThink_Gatherer)
                if "PhishTank:True" in sourceList:
                    PhishTank_Gatherer = modules.IoC_PhishTank()
                    objQueue.put(PhishTank_Gatherer)
                if "OpenPhish:True" in sourceList:
                    OpenPhish_Gatherer = modules.IoC_OpenPhish()
                    objQueue.put(OpenPhish_Gatherer)
                if "SANSEDU:True" in sourceList:
                    SANSEDU_Gatherer = modules.IoC_SANsEDU()
                    objQueue.put(SANSEDU_Gatherer)
                if "SpamHaus:True" in sourceList:
                    SpamHaus_Gatherer = modules.IoC_SpamHaus()
                    objQueue.put(SpamHaus_Gatherer)
                if "Zeus:True" in sourceList:
                    Zeus_Gatherer = modules.IoC_Zeus()
                    objQueue.put(Zeus_Gatherer)

                print ("Objects in Queue:", objQueue.qsize())

                objThreadsList = []

                for i in range (11):
                    while not objQueue.empty():
                        tempObject=objQueue.get()
                        objThread=Thread(target=tempObject.multiThreader)
                        objThreadsList.append(objThread)

                for x in objThreadsList:
                    x.run()
                print ("Process Complete: waiting an hour to run again")
                time.sleep(3600)
            else:
                print ("Nope not the right time to process, will wait an hour and try again..")
                time.sleep(3600)
    except KeyboardInterrupt:
        print('\n\n Keyboard exception received..')
        exit()