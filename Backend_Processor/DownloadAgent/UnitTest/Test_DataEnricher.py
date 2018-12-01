# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Unit Tests for Data Enricher Parent Class
# 
import unittest
import os
from shutil import copyfile
from DataEnricher import *

class Test_DataEnricher(unittest.TestCase):

	# def suite():
	# 	suite = unittest.TestSuite()
	# 	return suite

	# Test the ability to return a dictionary
	def test_return_data(self):
		finish = self.enrichObj.copyExtract()
		self.assertEqual(self.enrichObj.recordedThreats,finish)

	# Test Adding values to the SQL string
	def test_add_sql_values(self):
		self.enrichObj.addValues('test',['test1','test2'])
		self.assertTrue('WHERE' in self.enrichObj.sqlString)
		self.assertTrue('test' in self.enrichObj.sqlString)
		self.assertTrue('test1' in self.enrichObj.sqlString)
		self.assertTrue('test2' in self.enrichObj.sqlString)

	# Test updating databse location
	def test_change_db_loc(self):
		start = self.enrichObj.sqlDBloc
		self.enrichObj.set_sqlDBloc('test')
		self.assertNotEqual(start,self.enrichObj.sqlDBloc)

	# Test the reading of data from the SQL database 
	def test_extract_data(self):
		self.enrichObj.sqlString += " LIMIT 15 "
		self.enrichObj.extractFromDB()
		self.assertTrue(self.enrichObj.recordedThreats)

	def test_update_db(self):		
		# Pull Files to Test
		self.enrichObj.sqlString = "SELECT * FROM 'RecordedThreatsDB' LIMIT 15 "
		# Extract the Data
		self.enrichObj.extractFromDB()
		# Create truth values
		start_dict = dict()
		key_list = []
		for item in self.enrichObj.recordedThreats:
			start_dict[item] = dict()
			start_dict[item]['enriched'] = self.enrichObj.recordedThreats[item].get('enriched')
			if self.enrichObj.recordedThreats[item]['enriched'] == 'UnitTest':
				self.enrichObj.recordedThreats[item]['enriched'] = 'UnitTest2'
			else:
				self.enrichObj.recordedThreats[item]['enriched'] = 'UnitTest'
			key_list.append(self.enrichObj.recordedThreats[item]['threatKey'])

		# Push updates to DB
		self.enrichObj.updateDB()
		# Pull from database with the same keys
		self.enrichObj.sqlString = "SELECT * FROM 'RecordedThreatsDB' "
		self.enrichObj.addValues('threatKey',key_list)
		self.enrichObj.extractFromDB()

		# Count the number of values successfull changed
		count = 0
		for item in self.enrichObj.recordedThreats:
			if start_dict[item]['enriched'] != self.enrichObj.recordedThreats[item]['enriched']:
				count +=1

		# Return the values to normal
		for item in self.enrichObj.recordedThreats:
			self.enrichObj.recordedThreats[item]['enriched'] = 0
		self.enrichObj.updateDB()

		# Test Result
		self.assertEqual(len(self.enrichObj.recordedThreats),count)


	# Method to reduce the Number of Threats to the first 15 entries
	def prune_threats(self):
		num_threats = 1000
		# Create shortened lists and dictionaries
		tmp_dict = dict()
		# Extract dictionary keys
		keys = list(self.enrichObj.recordedThreats.keys())
		# Sort through first X threats
		for count in range(num_threats):
			tmp_dict[keys[count]] = self.enrichObj.recordedThreats[keys[count]]
		# Store new dictionary and lists
		self.enrichObj.recordedThreats = tmp_dict

	# Method to empty fields for enrichment
	def empty_key(self,key):
		for item in self.enrichObj.recordedThreats:
			self.enrichObj.recordedThreats[item][key] = ''

	#Start by creating an export instance 
	def setUp(self):
		self.enrichObj = DataEnricher()
		copyfile('./Database/Threats.sqlite','./UnitTest/UnitTestThreats.sqlite')
		self.enrichObj.set_sqlDBloc('./Database/UnitTestThreats.sqlite')


# if __name__ == '__main__':
# 	unittest.main()


	