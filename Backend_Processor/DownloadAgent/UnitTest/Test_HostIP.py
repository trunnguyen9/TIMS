# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Unit Tests for HostIP Enrichment Class
# 
import unittest
import os
from shutil import copyfile
from DataEnricher import *
from UnitTest import Test_DataEnricher

class Test_HostIP(Test_DataEnricher):	

	# Test the socket response from the Host IP modules
	def test_searchHostname(self):
		# Pull Data
		self.enrichObj.extractFromDB()
		# Reduce the number of threats for speed
		self.prune_threats()
		# Try searching for Host Names
		keyList = self.enrichObj.recordedThreats.keys()
		count = 0
		for key in keyList:
			ip = self.enrichObj.searchHostname(key)
			if not 'Failure' in ip[2]:
				count = count + 1
		# Check for failure
		self.assertTrue(count > 0)

	# Test the HostIP Modules Enrichment Method
	def test_HostIP_enrichment(self):
		# Pull Data
		self.enrichObj.extractFromDB()
		# Reduce the number of threats for speed
		self.prune_threats()
		# Empty Existing Field
		self.empty_key('rData')
		# Enrich Data
		self.enrichObj.enrichData()
		# Count the number of properly enriched entires
		count = 0
		for item in self.enrichObj.recordedThreats:
			if 'IP:' in self.enrichObj.recordedThreats[item]['rData']:
				count += 1
		# Check tha every entry was updates
		self.assertEqual(len(self.enrichObj.recordedThreats),count)

	# Test the HostIP Modules Enrichment Method
	def test_HostIP_enrichment_threaded(self):
		# Pull Data
		self.enrichObj.extractFromDB()
		# Reduce the number of threats for speed
		self.prune_threats()
		# Empty Existing Field
		self.empty_key('rData')
		# Enrich Data
		self.enrichObj.enrichData_threaded()
		# Count the number of properly enriched entires
		count = 0
		for item in self.enrichObj.recordedThreats:
			if 'IP:' in self.enrichObj.recordedThreats[item]['rData']:
				count += 1
		# Check tha every entry was updates
		self.assertEqual(len(self.enrichObj.recordedThreats),count)


	#Start by creating an export instance 
	def setUp(self):
		self.enrichObj = HostIP()
		self.sqlString = "SELECT * FROM 'RecordedThreatsDB' "
		copyfile('./Database/Threats.sqlite','./UnitTest/UnitTestThreats.sqlite')
		self.enrichObj.set_sqlDBloc('./Database/UnitTestThreats.sqlite')


