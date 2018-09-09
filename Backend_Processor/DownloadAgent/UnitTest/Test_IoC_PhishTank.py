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
from IoC_Modules import IoC_PhishTank #Import Emerging Threats IoC
from IoC_Modules import IoC_Methods

class Test_IoC_PhishTank(unittest.TestCase):

	def setUp(self):
		self.ThreatObject = IoC_PhishTank()	

	def suite():
	    suite = unittest.TestSuite()
	    suite.addTest(testCollectingResourceTest('testresource_connection'))
	    suite.addTest(testParseANewResourceTest('testresource_parsing'))
	    suite.addTest(testExportThreatListTest('testresource_return'))
	    suite.addTest(testCreateUniqueKey('testunique_key_creation'))
	    return suite

	#Test the ability of the module to connect with its resource via HTTP request 
	def testCollectingResourceTest(self):
		ThreatObject = IoC_Methods()
		ThreatObject.uri = 'http://data.PhishTank.com/data/online-valid.json'
		result = ThreatObject.pull()
		self.assertNotEqual(result,'')

	#Test the ability of the module to parse the resources' response
	def testParseANewResourceTest(self):
		# self.ThreatObject.pullPhishTank()
		self.assertIsInstance(self.ThreatObject.recordedThreats,dict)

	#Test the ability of the module to display all recorded threats
	def testViewThreatsTest(self):
		print('Under Construction')
		# threats = self.ThreatObject.getThreats()
		# self.ThreatObject.assertIsInstance(threats.get(1).getClass(),IoC_PhishTank)

	#Test the ability of the module to return an object containing recorded threats
	def testExportThreatListTest(self):
		# self.ThreatObject.pullPhishank()
		copy = self.ThreatObject.getThreats()
		self.assertIsInstance(copy,dict)

	# Test the ability of the module to create unique identifier keys
	def testCreateUniqueKey(self):
		keystrings = ['Fake Keystring1','Fake Keystring2']
		md5strings = []
		for entry in keystrings:
			m = hashlib.md5()
			m.update(entry.encode('utf-8'))
			md5strings.append(m.hexdigest())
		self.assertNotEqual(md5strings[0],md5strings[1])

if __name__ == '__main__':
	unittest.main()

