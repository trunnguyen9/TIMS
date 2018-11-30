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
import json
import csv
import os
from ExportAgent import *
from brothon import bro_log_reader

class Test_ExportModule(unittest.TestCase):

	def suite():
		suite = unittest.TestSuite()
		# suite.addTest(test_connect_resource('test_connect_resource'))
		# suite.addTest(test_extract_data('test_extract_data'))
		# suite.addTest(test_write_csv('test_write_csv'))
		# suite.addTest(test_write_tab('test_write_tab'))
		# suite.addTest(test_write_json('test_write_json'))
		# suite.addTest(test_write_bro('test_write_bro'))
		# suite.addTest(test_write_snort('test_write_snort'))
		return suite

	def test_extract_data(self):
		self.exportObj.extractFromDB()
		finish = self.exportObj.copyDict()
		self.assertNotEqual(dict(),finish)

	#Test the ability of the module to parse the resources' response
	def test_write_csv(self):
		#Extract Data
		self.exportObj.extractFromDB()
		#Reduce Threats
		self.prune_threats()
		#Write Test File
		self.exportObj.writeCSV()
		#Set the file string name
		file_string = self.exportObj.fileString + '.csv'
		
		# Load the test file into a new expected format
		full_list = []
		with open(file_string, "r") as infile:
			reader = csv.DictReader(infile)
			for row in reader:
				tmp_dict = dict()
				tmp_dict.update(row)
				full_list.append(tmp_dict)

		# Convert all entires of the main dictionary to strings
		for item in self.exportObj.threatList:
			keys = list(item.keys())
			for key in keys:
				item[key] = str(item[key])

		# self.assertNotEqual(full_list,[])
		self.assertEqual(full_list,self.exportObj.threatList)

	#Test the ability of the module to parse the resources' response
	def test_write_tab(self):
		#Extract Data
		self.exportObj.extractFromDB()
		#Reduce Threats
		self.prune_threats()
		#Write Test File
		self.exportObj.writeTab()
		#Set the file string name
		file_string = self.exportObj.fileString + '.txt'
		
		# Load the test file into a new expected format
		full_list = []
		with open(file_string, "r") as infile:
			reader = csv.DictReader(infile, delimiter='\t')
			for row in reader:
				tmp_dict = dict()
				tmp_dict.update(row)
				full_list.append(tmp_dict)

		# Convert all entires of the main dictionary to strings
		for item in self.exportObj.threatList:
			keys = list(item.keys())
			for key in keys:
				item[key] = str(item[key])

		# self.assertNotEqual(full_list,[])
		self.assertEqual(full_list,self.exportObj.threatList)

	# Test JSON Export Methods
	def test_write_json(self):
		# Extract Data
		self.exportObj.extractFromDB()
		# Reduce Threats
		self.prune_threats()
		# Write Test File
		self.exportObj.writeJSON()
		# Set the file string name
		file_string = self.exportObj.fileString + '.json'

		# Load the test file into a new expected format
		json_io = open(file_string)
		json_data = json.loads(json_io.read())

		#Check for equality
		self.assertEqual(json_data,self.exportObj.threatDict)

	def test_write_bro(self):
		# Extract Data
		self.exportObj.extractFromDB()
		# Reduce Threats
		self.prune_threats()
		# Write Test File
		self.exportObj.writeBro()
		# Set the file string name
		file_string = self.exportObj.fileString + '.bro'
		
		# Load the test file into a new expected format
		reader = bro_log_reader.BroLogReader(file_string)

		# Add each imported dictionary into a list
		full_list = []
		for row in reader.readrows():
			tmp_dict = dict()
			tmp_dict.update(row)
			full_list.append(tmp_dict)

		# Test Dictionary
		self.assertNotEqual(full_list,[])

	def test_write_snort(self):
		# Extract Data with legitimate ipv4 values
		self.exportObj.addValues('iType',['ipv4'])
		self.exportObj.extractFromDB()
		# Reduce Threats
		self.prune_threats()
		# Write Test File
		self.exportObj.writeSNORT()
		# Set the file string name
		file_string = self.exportObj.fileString + '.snort'

		# Load the test file into a new expected format
		full_list = []
		with open(file_string, "r") as infile:
			full_list = infile.readlines()
		print(len(full_list))
		# Test Dictionary
		self.assertNotEqual(full_list,[])

	def test_ExportRecordedThreats(self):
		# Overwrite existing export object
		self.exportObj = ExportRecordedThreats()
		# Call only function
		result = self.exportObj.exportRTStatisticByProvider()
		print(type(result))
		self.assertNotEqual(result,dict())

	def test_ExportThreatStats(self):
		self.exportObj = ExportThreatStats()
		sqlReturn = self.exportObj.exportThreatStats()
		self.assertNotEqual(sqlReturn,'')

	# Method to reduce the Number of Threats to the first 15 entries
	def prune_threats(self):
		num_threats = 15
		# Create shortened lists and dictionaries
		tmp_list = list()
		tmp_dict = dict()
		# Extract dictionary keys
		keys = list(self.exportObj.threatDict.keys())
		# Sort through first X threats
		for count in range(num_threats):
			tmp_list.append(self.exportObj.threatList[count])
			tmp_dict[keys[count]] = self.exportObj.threatDict[keys[count]]
		# Store new dictionary and lists
		self.exportObj.threatList = tmp_list
		self.exportObj.threatDict = tmp_dict

	#Start by creating an export instance 
	def setUp(self):
		self.exportObj = ExportSQL('./')
		self.exportObj.updateDBloc('./Database')

	#Clean up all Written Files
	def tearDown(self):
		try:
			extensions = ['.csv','.json','.bro','.txt','.snort']
			for ext in extensions:
				file_str = self.exportObj.fileString + ext
				if os.path.exists(file_str):
					os.remove(file_str)
		except:
			pass

		

if __name__ == '__main__':
	unittest.main()


	