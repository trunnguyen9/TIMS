# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Unit Tests for All IoC Modules
# 
import unittest
import hashlib
import _sqlite3
from modules import *

class Test_IoC(unittest.TestCase):


	# Test the ability of the module to create unique identifier keys
	def test_create_unique_key(self):
		keystrings = ['Fake Keystring1','Fake Keystring2']
		md5strings = []
		for entry in keystrings:
			m = hashlib.md5()
			m.update(entry.encode('utf-8'))
			md5strings.append(m.hexdigest())
		self.assertNotEqual(md5strings[0],md5strings[1])

	#Test ability of module to insert threat into database
	def test_db_insert(self):
		try:
			# Collect Threats from Source
			self.ThreatObject.pull(self.ThreatObject.urlList[0])

			# Connect to SQL database
			con = _sqlite3.connect('./Database/Threats.sqlite')
			cursor = con.cursor()
			# Begin SQL String
			sqlString = "SELECT * FROM 'ThreatStatsDB'"

			keyList =  ['startTime','endTime'];
			# Extract the key and values that were just inserted
			for key in keyList:
				sqlString = self.addValues(sqlString,key,[self.ThreatObject.TIMSlog[key]])
			sqlString += " ;"

			# Pull and Parse the result from the SQL table
			sqlResult = cursor.execute(sqlString)
			threatStats = [dict(zip([key[0] for key in cursor.description], row)) for row in sqlResult]

			# Check that the resource connection was correct
			self.assertNotEqual(self.ThreatObject.threatCounter,0)
			# Check that the entry was able to be found
			self.assertNotEqual(threatStats,[])
			# Check that there were not errors inserting data into the database
			self.assertEqual(int(threatStats[0]['lineCount']),int(threatStats[0]['newCount'])+int(threatStats[0]['dupeCount']))

			# Close connections
			cursor.close()
			con.close()
		except:
			pass


	def addValues(self,sqlString, colName, valueList):
		# Check to see if a where clause already exists, if not add it
		if 'WHERE' not in sqlString:
			sqlString += " WHERE "
		else:
			sqlString += " AND "
		# Add the column name to parse through and start the acceptable list
		if colName not in sqlString:
			sqlString += "  " + colName + " IN ("
		# Iterate through all list items and add to list
		for item in valueList:
			# print(type(item))
			sqlString += '\'' + str(item) + '\','
		# Remove final comma from string
		if sqlString.endswith(','):
			sqlString = sqlString[:-1]
		# Close List Parenthesies
		sqlString += ")"
		return sqlString


# if __name__ == '__main__':
# 	unittest.main()

