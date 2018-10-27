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
# @TODO Read Configuration File made from GUI Front End
# @TODO Connect to sqllite database -- DONE
# @TODO Connect to threat databases (TDs)
# @TODO Normalize information from TDs and put them in the same format -- DONE
# @TODO Enrich threat data - add more information to what comes from the TDs
# @TODO          - IP addresses need DNS info, GPS info
# @TODO          - FQDN, DNS need IP address resolved, and GPS info
# @TODO          - email address : no idea how we can enrich
# @TODO          - MD5/SHA1 hash of malware/virus: no idea how we can enrich
# @TODO   * Don't know if we can do this as we ingest the data, or if it will take too long. Might be better
# @TODO   * to ingest quickly then have another agent that goes back and enriches the data, as another process
# @TODO lots and lots of error checking


# --====================================================--
# Import Necessary Libraries
# --====================================================--

from datetime import datetime
import modules
from threading import Thread
from queue import Queue

from pprint import pprint
import time


# __MAIN__

# create SQLite DB Connection
#SQLiteDataStore = DataStore_Modules.DataStore_SQLite.SQLiteDataStore()

# create main DataStore for all threat information
# threatDataStore = DataStore_Modules.DataStore_Internal.interalDataStore()

# create a time object to obtain current time
todayDateTime = datetime.now()

try:
    objQueue = Queue()

    startTime= datetime.utcnow()
    NetLabs360_Gatherer = modules.IoC_NetLabs360()
    AlienVault_Gatherer = modules.IoC_AlienVault()
    EmergingThreats_gatherer = modules.IoC_EmergingThreats()
    FedoTracker_Gatherer = modules.IoC_Feodotracker()
    NoThink_Gatherer = modules.IoC_NoThink()
    PhishTank_Gatherer = modules.IoC_PhishTank()
    OpenPhish_Gatherer = modules.IoC_OpenPhish()
    SANSEDU_Gatherer = modules.IoC_SANsEDU()
    SpamHaus_Gatherer = modules.IoC_SpamHaus()
    Zeus_Gatherer = modules.IoC_Zeus()

    objQueue.put(NetLabs360_Gatherer)
    objQueue.put(AlienVault_Gatherer)
    objQueue.put(EmergingThreats_gatherer)
    objQueue.put(FedoTracker_Gatherer)
    objQueue.put(NoThink_Gatherer)
    objQueue.put(PhishTank_Gatherer)
    objQueue.put(OpenPhish_Gatherer)
    objQueue.put(SANSEDU_Gatherer)
    objQueue.put(SpamHaus_Gatherer)
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

except KeyboardInterrupt:
    print ('\n\n Keyboard exception recieved..')
    exit()

