# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Unit Tests for GeoIP Enrichment Class
# 
import unittest
import os
import geoip2
from shutil import copyfile
from DataEnricher import *
from UnitTest import Test_DataEnricher

class Test_LocateGeoIP(Test_DataEnricher):	

	# Test DB Location Adjustment Methods
	def test_dbloc_updates(self):
		# Pull Starting Locations
		asnDBloc = self.enrichObj.asnDBloc 
		cityDBloc = self.enrichObj.cityDBloc 
		countryDBloc = self.enrichObj.countryDBloc
		# Change Locations
		self.enrichObj.set_asnDBloc('test')
		self.enrichObj.set_cityDBloc('test')
		self.enrichObj.set_countryDBloc('test')
		# Test for change
		self.assertNotEqual(self.enrichObj.asnDBloc,asnDBloc)
		self.assertNotEqual(self.enrichObj.cityDBloc,cityDBloc)
		self.assertNotEqual(self.enrichObj.cityDBloc,cityDBloc)

	# # Test the socket response from the Host IP modules
	# def test_searchASN(self):
	# 	# Open the Reader
	# 	self.enrichObj.reader = geoip2.database.Reader(self.enrichObj.asnDBloc)
	# 	# Pull Data
	# 	self.enrichObj.extractFromDB()
	# 	# Reduce the number of threats for speed
	# 	self.prune_threats()
	# 	# Try searching for ASN Information
	# 	count = 0
	# 	for item in self.enrichObj.recordedThreats:
	# 		ip = self.enrichObj.searchASN(item)
	# 		if not " - Failure" in ip[0]:
	# 			count += 1
	# 	#Close the Reader
	# 	self.enrichObj.reader.close()
	# 	# Check for failure
	# 	self.assertTrue(count > 0)

	# # Test the socket response from the Host IP modules
	# def test_searchCity(self):
	# 	# Open the Reader
	# 	self.enrichObj.reader = geoip2.database.Reader(self.enrichObj.cityDBloc)
	# 	# Pull Data
	# 	self.enrichObj.extractFromDB()
	# 	# Reduce the number of threats for speed
	# 	self.prune_threats()
	# 	# Try searching for City Information
	# 	count = 0
	# 	for item in self.enrichObj.recordedThreats:
	# 		ip = self.enrichObj.searchASN(item)
	# 		if not " - Failure" in ip[0]:
	# 			count += 1
	# 	#Close the Reader
	# 	self.enrichObj.reader.close()
	# 	# Check for failure
	# 	self.assertTrue(count > 0)

	# Test the HostIP Modules Enrichment Method
	def test_GeoIP_enrichment(self):
		# Pull Data
		self.enrichObj.extractFromDB()
		# Reduce the number of threats for speed
		self.prune_threats()
		# Empty Existing Field
		self.empty_key('enriched')
		# Enrich Data
		self.enrichObj.enrichData()
		# Count the number of properly enriched entires
		count = 0
		for item in self.enrichObj.recordedThreats:
			if self.enrichObj.recordedThreats[item]['enriched'] == 1:
				count += 1
		# Check tha every entry was updates
		self.assertEqual(len(self.enrichObj.recordedThreats),count)

	#Start by creating an export instance 
	def setUp(self):
		self.enrichObj = LocateGeoIP()
		self.enrichObj.sqlString = "SELECT * FROM 'RecordedThreatsDB' "
		copyfile('./Database/Threats.sqlite','./UnitTest/UnitTestThreats.sqlite')
		self.enrichObj.set_sqlDBloc('./UnitTest/UnitTestThreats.sqlite')


