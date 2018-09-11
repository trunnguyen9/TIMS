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
# @TODO Connect to sqllite database
# @TODO Connect to threat databases (TDs)
# @TODO Normalize information from TDs and put them in the same format
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
from pprint import pprint

import DataStore_Modules
import IoC_Modules


# __MAIN__
# create main DataStore for all threat information
threatDataStore = DataStore_Modules.DataStore_Internal.interalDataStore()

# create a time object to obtain current time
todayDateTime=datetime.now()

# get current hour, this will be used to determine which processes are run
currentHour=todayDateTime.hour

# python doesnt have a case statement, so you have to use a bunch of if statements
# different threat libraries are updated at different time intervals, everything from updated every hour to once a day
# these conditional statements will be used to download the proper threat libraries at the proper time interval. If you
# to download too often, many will block you. So we cant annoy them too much or we'll get blocked.

# -- ================ --
# PhishTank Test Data
# -- ================ --
#
# This is just a basic test to pull data from one open source threat library and dump it into the database
# so we have some real data in the database, so everyone can see the workflow that i think will work..
# Once we get this working for one library, it will be just a matter of making modules for the other threat libraries
#

# -- Emerging Threats Open Source Threat Library --
# creates the object to connect to the Emerging Threats Open Source Library
EmergingThreats_gatherer = IoC_Modules.IoC_EmergingThreats()

# performs actions needed to pull the data from the online resource and puts the data into a dictionary item in the right
# format. The data will just sit in the data dictionary until you put it into the database.
EmergingThreats_gatherer.pullEmergingThreats()

# Moves the data from the emerging threats object to the main internal data object
threatDataStore.addDataToStore(EmergingThreats_gatherer.getThreats())


# HUGE database takes a WHILE to download and process.. will multithread it to speed it up drastically
# -- Phish Tank Open Source List --
# creates the object to connect to the phishtank opensource library
#PhishTank_gatherer = IoC_Modules.IoC_PhishTank()

# performs actions needed to pull the data from the online resource and puts the data into a dictionary item in the right
# format. The data will just sit in the data dictionary until you put it into the database.
#PhishTank_gatherer.pullPhishtank()

# Moves the data from the phishtank object to the main internal data object
#threatDataStore.addDataToStore(PhishTank_gatherer.getThreats())

'''
if (currentHour%1)==0:
	print ("DO EVERY HOUR!")
if (currentHour%2)==0:
	print ("DO EVERY TWO HOURS!")
if (currentHour%4)==0:
	print ("DO EVERY FOUR HOURS")
if (currentHour%6)==0:
	print ("DO EVERY SIX HOURS!")
if (currentHour%12)==0:
	print ("DO EVERY TWELVE HOUR!")
if (currentHour%24)==0:
	print ("DO EVERY TWENTY FOUR HOURS!")
	# -- Phish Tank Open Source List -- 
    # creates the object to connect to the phishtank opensource library
    #PhishTank_gatherer = IoC_Modules.IoC_PhishTank()
    
    # performs actions needed to pull the data from the online resource and puts the data into a dictionary item in the right
    # format. The data will just sit in the data dictionary until you put it into the database.
    #PhishTank_gatherer.pullPhishtank()
    
    # Moves the data from the phishtank object to the main internal data object
    #threatDataStore.addDataToStore(PhishTank_gatherer.getThreats())
'''

# creates sql object and writes data to sqlite database
SQLiteDataStore = DataStore_Modules.DataStore_SQLite.SQLiteDataStore(threatDataStore.getDataStore())
SQLiteDataStore.processNewThreats()
SQLiteDataStore.recordStats()