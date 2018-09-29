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
from pprint import pprint

import DataStore_Modules
import IoC_Modules


# __MAIN__

# create SQLite DB Connection
SQLiteDataStore = DataStore_Modules.DataStore_SQLite.SQLiteDataStore()

# create main DataStore for all threat information
#threatDataStore = DataStore_Modules.DataStore_Internal.interalDataStore()

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
'''
EmergingThreats_gathererv2 = IoC_Modules.IoC_EmergingThreatsv2(SQLiteDataStore.getDBConn())
EmergingThreats_gathererv2.pull()

AlienVault_gatherer = IoC_Modules.IoC_AlienVault(SQLiteDataStore.getDBConn())
AlienVault_gatherer.pull()

try :
	CSIRTG_gatherer = IoC_Modules.IoC_CSIRTG(SQLiteDataStore.getDBConn())
	CSIRTG_gatherer.pull()
except:
	print ("error with CSIRTG")


PhishTank_gathererv2 = IoC_Modules.IoC_PhishTankv2(SQLiteDataStore.getDBConn())
PhishTank_gathererv2.pull()

FeodoTracker_gatherer = IoC_Modules.IoC_Feodotracker(SQLiteDataStore.getDBConn())
FeodoTracker_gatherer.pull()

Zeus_gatherer = IoC_Modules.IoC_Zeus(SQLiteDataStore.getDBConn())
Zeus_gatherer.pull()

NoThink_gatherer = IoC_Modules.IoC_NoThink(SQLiteDataStore.getDBConn())
NoThink_gatherer.pull()

OpenPhish_gatherer = IoC_Modules.IoC_OpenPhish(SQLiteDataStore.getDBConn())
OpenPhish_gatherer.pull()

SANsEDU_gatherer = IoC_Modules.IoC_SANsEDU(SQLiteDataStore.getDBConn())
SANsEDU_gatherer.pull()
'''

SpamHaus_Gatherer = IoC_Modules.IoC_SpamHaus(SQLiteDataStore.getDBConn())
SpamHaus_Gatherer.pull()
