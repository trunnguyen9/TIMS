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
import hashlib
from Backend_Processor.DownloadAgent.IoC_Modules import IoC_EmergingThreats #Import EmergingThreats IoC


class IoC_Module_UnitTests(unittest.TestCase)

	# /*
	# Example Test Format
	# #Test -- Not Corrected From Java
	# def  ExampleTest(){
	#  // This test should pass
	#  self.assertTrue(1==1)
	# }

	# #Test -- Not Corrected From Java
	# def  ExampleTest2(){
	#  // This test should fail
	#  self.assertTrue(1==0)
	# }
	#  */

	#Test the ability of the module to connect with its resource via HTTP request 
	def  CollectingResourceTest(self):
		self.pullEmergingThreats()
		uri = 'http://data.EmergingThreats.com/data/online-valid.json'
		result = HGMMethods.CreateHTTPRequest(uri)
		self.assertTrue(result.contains("HTTP POST"))

	#Test the ability of the module to parse the resources' response
	def  ParseANewResourceTest(self):
		self.pullEmergingThreats()
		self.assertIsInstance(self.recordedTheats,dict())

	#Test the ability of the module to display all recorded threats
	def  ViewThreatsTest(self):
		# threats = self.getThreats()
		# self.assertIsInstance(threats.get(1).getClass(),IoC_EmergingThreats)

	#Test the ability of the module to return an object containing recorded threats
	def  ExportThreatListTest(self):
		self.pullEmergingThreats()
		copy = self.getThreats()
		self.assertIsInstance(copy,dict())

	# Test the ability of the module to create unique identifier keys
	def CreateUniqueKey(self):
		keystrings = ['Fake Keystring1','Fake Keystring2']
		mdsStrings = []
		for item in keystrings:
			m = hashlib.md5()
			m.update(keystring1.encode('utf-8'))
			md5strings.append(m.hexdigest())
		self.assertNotEqual(md5string[0],md5string[1])



if __name__ == '__main__':
 unittest.main()