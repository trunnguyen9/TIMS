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
# This is the "hunter/gatherer" (aka enricher) of this system. It will go through multiple sites and pull the
#  information
# --====================================================--


# --====================================================--
# Import Necessary Libraries
# --====================================================--

from datetime import datetime
import modules
from threading import Thread
from queue import Queue
import json

# __MAIN__

if __name__ == '__main__':
    # create a time object to obtain current time
    todayDateTime = datetime.now()
    sourceList =[]

    try:
        objQueue = Queue()
        # Opens configuration file created by web front end interface
        with open('config.json', 'r') as configFile:
            data = json.load(configFile)

        # pulls interval from configuration file. This interval is the interval in
        # which to pull from the threat libraries
        hourInterval = int(data['time'])
        currentHour = datetime.utcnow().hour

        # for testing
        # hourInterval=1
        # print ("currentHour", currentHour,"interval:",data['time'],"mod:", (currentHour % hourInterval))

        # compares interval from configuration file to current hour
        if currentHour % hourInterval == 0:
            print ("its the right time to process!: processing!!!")
            startTime= datetime.utcnow()

            # builds the list of datafeeds from the configuation file
            for item in data['feedSources']:
                sourceItem = item['name']+":"+str(item['selected'])
                sourceList.append(sourceItem)

            # if feedname:True process the datafeed
            # This enabling/disabling datafeeds is handled through the web interface
            # that saves to the configuration file

            if "AlienVault:True" in sourceList:
                AlienVault_Gatherer = modules.IoC_AlienVault()
                objQueue.put(AlienVault_Gatherer)

            if "EmergingThreats:True" in sourceList:
                EmergingThreats_gatherer = modules.IoC_EmergingThreats()
                objQueue.put(EmergingThreats_gatherer)

            if "NoThink:True" in sourceList:
                NoThink_Gatherer = modules.IoC_NoThink()
                objQueue.put(NoThink_Gatherer)

            if "PhishTank:True" in sourceList:
                PhishTank_Gatherer = modules.IoC_PhishTank()
                objQueue.put(PhishTank_Gatherer)

            if "OpenPhish:True" in sourceList:
                OpenPhish_Gatherer = modules.IoC_OpenPhish()
                objQueue.put(OpenPhish_Gatherer)

            if "SANsEDU:True" in sourceList:
                SANSEDU_Gatherer = modules.IoC_SANsEDU()
                objQueue.put(SANSEDU_Gatherer)

            if "SpamHaus:True" in sourceList:
                SpamHaus_Gatherer = modules.IoC_SpamHaus()
                objQueue.put(SpamHaus_Gatherer)

            if "Zeus:True" in sourceList:
                Zeus_Gatherer = modules.IoC_Zeus()
                objQueue.put(Zeus_Gatherer)

            if "NetLab360:True" in sourceList:
                NetLabs360_Gatherer = modules.IoC_NetLabs360()
                objQueue.put(NetLabs360_Gatherer)

            if "Feodotracker:True" in sourceList:
                FedoTracker_Gatherer = modules.IoC_Feodotracker()
                objQueue.put(FedoTracker_Gatherer)
            # print ("Objects in Queue:", objQueue.qsize())

            # create list for multiThreading
            objThreadsList = []

            for i in range (11):
                while not objQueue.empty():
                    tempObject=objQueue.get()
                    objThread=Thread(target=tempObject.multiThreader)
                    objThreadsList.append(objThread)

            for x in objThreadsList:
                x.run()
            print ("Process Complete: waiting an hour to run again")

    except KeyboardInterrupt:
        print('\n\n Keyboard exception received..')
        exit()