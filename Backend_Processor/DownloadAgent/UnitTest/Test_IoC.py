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
import _sqlite3
from modules import *

class Test_IoC(unittest.TestCase):

	SQLiteDataStore = SQLiteDataStore()

	# Set up the Unit Test Suite for a Generic IoC Module
	def suite():
		suite = unittest.TestSuite()
		# suite.addTest(test_connect_resource('test_connect_resource'))
		suite.addTest(test_create_unique_key('test_create_unique_key'))
		# suite.addTest(test_parse_resource('test_parse_resource'))
		# suite.addTest(test_db_insert('test_db_insert'))
		# suite.addTest(test_view_threats('test_view_threats'))
		return suite

	# Test the ability of the module to create unique identifier keys
	def test_create_unique_key(self):
		keystrings = ['Fake Keystring1','Fake Keystring2']
		md5strings = []
		for entry in keystrings:
			m = hashlib.md5()
			m.update(entry.encode('utf-8'))
			md5strings.append(m.hexdigest())
		self.assertNotEqual(md5strings[0],md5strings[1])

	#Test the ability of the module to parse the resources' response
	def test_parse_resource(self):
		self.ThreatObject.pull()
		# Empty Dictionaries Assert to False, therefore test if dictionary is not empty
		self.assertTrue(self.ThreatObject.recordedThreats)

	#Test ability of module to insert threat into database
	def test_db_insert(self):
		# Start by pulling from the database and attempting an insert
		self.ThreatObject.pull()
		self.ThreatObject.addToDatabase2()
		# Connect to SQL database
		con = _sqlite3.connect('./Database/Threats.sqlite')
		cursor = con.cursor()
		count = 0
		# Extract the key from each threat to search for
		for threatNum in self.ThreatObject.recordedThreats:
			# Extract from the database using threat key and check that data was returned
			threatKey = self.ThreatObject.recordedThreats[threatNum]['threatkey']
			sqlResult = cursor.execute("SELECT * FROM 'RecordedThreatsDB' WHERE 'threatKey' = \'" + threatKey + "\' ;")
			if sqlResult != '':
				count = count + 1
		self.assertEqual(count,len(self.ThreatObject.recordedThreats))


	# #Test the ability of the module to display all recorded threats
	# def test_view_threats(self):
	# 	self.ThreatObject.showThreats()

if __name__ == '__main__':
	unittest.main()

