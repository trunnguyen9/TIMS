# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Baseline object to provide read and update capabilities 
# for data enrichment tools 
# 
from datetime import datetime
import _sqlite3
import sys
import time
import socket

class DataEnricher:

	recordedThreats = dict()
	sqlDBloc = '../../../Threats.sqlite'
	modtime = ''
	sqlString = "SELECT * FROM 'RecordedThreatsDB' "

	def __init__(self):
		#Collect current time to update database with
		self.modtime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	def updateDBloc(self,newLoc):
		self.sqlDBloc = newLoc

	def copyExtract(self):
		return self.recordedThreats

	def displayExtract(self):
		for item in self.recordedThreats:
			print(self.recordedThreats[item])

	def extractFromDB(self):
		print ("Connecting to Recorded Threats DB for extracting IOCs...")
		# Construct SQL String
		self.sqlString = self.sqlString + ";"
		# Connect to SQL Database
		con = _sqlite3.connect(self.sqlDBloc)
		cursor = con.cursor()
		sqlResult = cursor.execute(self.sqlString)

		# iterate through each row/entry for the resturned query, using description to fetch key names
		threatList = [dict(zip([key[0] for key in cursor.description],row)) for row in sqlResult]
		for item in threatList:
			tempKey = item.get('threatKey')
			self.recordedThreats[tempKey] = item

		# Close the connection to the database
		con.commit()
		con.close()
	# end extractFromDB

	def updateDB(self):
		# Connect to the Threats Database
		con = _sqlite3.connect(self.sqlDBloc)
		cursor= con.cursor()

		# Construct SQL String to Get the First Line of the Database
		pullString = "SELECT * FROM RecordedThreatsDB ORDER BY ROWID ASC LIMIT 1;"
		# Get the Existing Column Names
		pullResult = cursor.execute(pullString)
		# iterate through each row/entry for the resturned query, using description to fetch key names
		threatList = [dict(zip([key[0] for key in cursor.description],row)) for row in pullResult]
		# Find the Existing Keys in the Database
		currentKeys = threatList[0].keys()

		# Begin SQL String
		sqlString = "UPDATE 'RecordedThreatsDB' SET "
		# Make certain all dictionary entries have a column to be inserted into
		example_key = list(self.recordedThreats.keys())[0]
		for key in self.recordedThreats[example_key]:
			# Add Key to SQL Update String
			sqlString +=  str(key) + "=?,"
			# If the Given Key is Not in the Current Database, Add it
			if not key in currentKeys:
				try:
					cursor.execute("ALTER TABLE 'RecordedThreatsDB' ADD COLUMN " + key + " ;")
				except:
					pass

		# Remove trailing comma and finish string
		sqlString = sqlString[:-1]
		sqlString += " WHERE threatKey=? ;"

		# Construct a tuple to insert into the database
		entries = []
		# Iterate through threats
		for item in self.recordedThreats:
			params = []
			for key in self.recordedThreats[item]:
				try:
					params.append(self.recordedThreats[item][key])
				except:
					# If the first entry doesn't work try inserting a blank vaue
					params.append('')
			params.append(item)
			entries.append(params)

		# Push Update SQL Requests
		print('Pushing Enrichment to Thereat Database...')
		cursor.executemany(sqlString, entries)

		# Close the SQL Connection
		con.commit()
		con.close()		

	def addValues(self,colName,valueList):
		# Check to see if a where clause already exists, if not add it
		if 'WHERE' not in self.sqlString:
			self.sqlString += " WHERE "
		else:
			self.sqlString += " OR "
		# Add the column name to parse through and start the acceptable list
		if colName not in self.sqlString:
			self.sqlString += "  " + colName + " in ("
		# Iterate through all list items and add to list
		for item in valueList:
			# print(type(item))
			self.sqlString += '\'' + item + '\','
		# Remove final comma from string
		if self.sqlString.endswith(','):
			self.sqlString = self.sqlString[:-1]
		#Close List Parenthesies
		self.sqlString += ")" 

	def print_line(self,string):
		sys.stdout.flush()
		sys.stdout.write('\r' + string)

	# Method to Check if string is IPV4 IP address
	def is_valid_ipv4_address(self,address):
		try:
			socket.inet_pton(socket.AF_INET, address)
		except AttributeError:  # no inet_pton here, sorry
			return False
		except socket.error:  # not a valid address
			return False
		return True

	# Method to Check if string is IPV6 IP address
	def is_valid_ipv6_address(self,address):
		try:
			socket.inet_pton(socket.AF_INET6, address)
		except socket.error:  # not a valid address
			return False
		return True	
	# end updateDB


if __name__ == '__main__':
	test = DataEnricher()
	test.extractFromDB()
	# test.displayExtract()
	test.updateDB()






