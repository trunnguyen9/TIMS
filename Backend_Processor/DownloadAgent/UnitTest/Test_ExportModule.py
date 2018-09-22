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

class Test_ExportModule(unittest.TestCase):

	def suite():
		suite = unittest.TestSuite()
		# suite.addTest(test_connect_resource('test_connect_resource'))
		suite.addTest(test_extract_data('test_extract_data'))
		suite.addTest(test_write_csv('test_write_csv'))
		suite.addTest(test_write_json('test_write_json'))
		return suite


	def test_extract_data(self):
		self.exportObj.extractFromDB()
		finish = self.exportObj.copyDict()
		self.assertNotEqual(dict(),finish)

	#Test the ability of the module to parse the resources' response
	def test_write_csv(self):
		#Extract Data
		self.exportObj.extractFromDB()
		#Write Test File
		self.exportObj.writeCSV()
		csv_string = self.exportObj.fileString + '.csv'
		# with open(csv_string) as f:
		full_list = []
		with open(csv_string, "r") as infile:
			reader = csv.DictReader(infile)
			for row in reader:
				tmp_dict = dict()
				tmp_dict.update(row)
				full_list.append(tmp_dict)
		self.assertNotEqual(full_list,[])

	def test_write_json(self):
		# Extract Data
		self.exportObj.extractFromDB()
		# Write Test File
		self.exportObj.writeJSON()
		# Load the test file into a new expected format
		json_file = self.exportObj.fileString + '.json'
		json_io = open(json_file)
		json_data = json.loads(json_io.read())
		#Check for equality
		self.assertEqual(json_data,self.exportObj.threatDict)


	#Start by creating an export instance 
	def setUp(self):
		self.exportObj = ExportSQL('./')
		self.exportObj.sql_db_loc = '../../Threats.sqlite'

	#Clean up all Written Files
	def tearDown(self):
		extensions = ['.csv','.json']
		for ext in extensions:
			file_str = self.exportObj.fileString + ext
			if os.path.exists(file_str):
				os.remove(file_str)
		self.exportObj = None
		self.exportObj = ExportSQL('./')

		

if __name__ == '__main__':
	unittest.main()

	