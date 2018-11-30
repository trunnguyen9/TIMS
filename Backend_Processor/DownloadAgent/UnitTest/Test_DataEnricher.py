# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Unit Test Object with methods for assessing functionality of
# TIMS IoC Module
import unittest
import os
from DataEnricher import *

class Test_DataEnricher(unittest.TestCase):

	def suite():
		suite = unittest.TestSuite()
		return suite

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

		

if __name__ == '__main__':
	unittest.main()


	