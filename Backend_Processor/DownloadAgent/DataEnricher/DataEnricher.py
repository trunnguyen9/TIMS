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
		sqlString = "SELECT * FROM 'RecordedThreatsDB' ;"
		con = _sqlite3.connect(self.sqlDBloc)
		cursor = con.cursor()
		sqlResult = cursor.execute(sqlString)

		# iterate through each row/entry for the resturned query, using description to fetch key names
		threatList = [dict(zip([key[0] for key in cursor.description],row)) for row in sqlResult]
		for item in threatList:
			tempKey = item.get('threatKey')
			self.recordedThreats[tempKey] = item
		con.commit()
		con.close()
	# end extractFromDB

	def updateDB(self):
		currentDateTime = datetime.now()
		con = _sqlite3.connect(self.sqlDBloc)
		cursor= con.cursor()
		# sqlResult = cursor.execute("PRAGMA table_info('RecordedThreatsDB')");

		print('Pushing Enrichment to Thereat Database...')
		example_key = list(self.recordedThreats.keys())[0]
		# Make certain all dictionary entries have a column to be inserted into
		for key in self.recordedThreats[example_key]:
			try:
				cursor.execute("ALTER TABLE 'RecordedThreatsDB' ADD COLUMN " + key + ";")
			except:
				pass
		for item in self.recordedThreats:
			# Set the last time to the current time
			# self.recordedThreats[item]['lastTime'] = str(currentDateTime)
			for key in self.recordedThreats[item]:
				try:
					# Attempt to inset extracted value
					sqlString = "UPDATE 'RecordedThreatsDB' SET " 
					sqlString += key  + " = " + "\'" +  str(self.recordedThreats[item][key]) + "\'" 
					sqlString += " WHERE threatKey = " + "\'" + self.recordedThreats[item]['threatKey'] + "\'" + " ;"
					cursor.execute(sqlString)
				except:
					# If the first entry doesn't work try inserting a blank vaue
					try:
						sqlString = "UPDATE 'RecordedThreatsDB' SET " 
						sqlString += key  + " = " + "\'" + "\'" 
						sqlString += " WHERE threatKey = " + "\'" + self.recordedThreats[item]['threatKey'] + "\'" + " ;"
						cursor.execute(sqlString)
					except:
						pass
					
		con.commit()
		con.close()

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

	# def updateDB(self):
	# 	currentDateTime = datetime.now()
	# 	con = _sqlite3.connect(self.sqlDBloc)
	# 	cursor= con.cursor()
	# 	sqlResult = cursor.execute("PRAGMA table_info('RecordedThreatsDB')");

	# 	progressBarTicker = 0
	# 	print('Pushing Enrichment to Thereat Database...')
	# 	example_key = list(self.recordedThreats.keys())[0]
	# 	# Make certain all dictionary entries have a column to be inserted into
	# 	for key in self.recordedThreats[example_key]:
	# 		try:
	# 			cursor.execute("ALTER TABLE 'RecordedThreatsDB' ADD COLUMN " + key + ";")
	# 		except:
	# 			pass
		
	# 	sqlString = ["UPDATE RecordedThreatsDB SET"] 
	# 		for key in self.recordedThreats[item]:
	# 		for key in self.recordedThreats[item]:
	# 			sqlString.append(key  + str(self.recordedThreats[item][key]) + ",")
	# 		sqlString = sqlString[:-1]
	# 		sqlString.append(" WHERE 'threatKey' = " + self.recordedThreats[item]['threatKey'] + ";")
	# 		cursor.execute(sqlString)


if __name__ == '__main__':
	test = DataEnricher()
	test.extractFromDB()
	# test.displayExtract()
	test.updateDB()






