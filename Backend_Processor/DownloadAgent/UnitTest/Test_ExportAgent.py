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
import json
import csv
from ExportAgent import *

class Test_ExportAgent(unittest.TestCase):


	def setUp(self):
		self.exportObj = SQL_Export('./')
		self.exportObj.extractFromDB()

	def suite():
	    suite = unittest.TestSuite()
	    # suite.addTest(test_connect_resource('test_connect_resource'))
	    suite.addTest(test_write_csv('test_write_csv'))
	    suite.addTest(test_write_json('test_write_json'))
	    return suite

	# #Test the ability of the module to connect with its resource via HTTP request 
	# def test_connect_resource(self):
	# 	start = self.ThreatObject.recordedThreats
	# 	self.ThreatObject.pull()
	# 	# If the dictionary does not update after the pull, the connection likely did not work
	# 	self.assertNotEqual(start,self.ThreatObject.recordedThreats)

	#Test the ability of the module to parse the resources' response
	def test_write_csv(self):
		self.exportObj.writeCSV()
		csv_string = self.exportObj.fileString + '.csv'
		with open(csv_string) as f:
		    self.assertEqual(f,self.exportObj.threatDict)


	def test_write_json(self):
		self.exportObj.writeJSON()
		json_string = self.exportObj.fileString + '.json'
		with open(json_string) as f:
		    self.assertEqual(f,self.exportObj.threatDict)

if __name__ == '__main__':
	unittest.main()

	