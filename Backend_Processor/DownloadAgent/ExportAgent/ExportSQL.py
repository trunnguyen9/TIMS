# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# simple methods used for exporting data from SQLlite database

from pprint import pprint
from datetime import datetime
import _sqlite3
import json
import csv
# import FrontEnd_GUI
# import PySimpleGUI as sg

class SQL_Export:

	threatList = []
	threatDict = dict()
	fileString = ''
	log = dict()
	errorLog = dict()
	sqlStringDict = dict()


	def __init__(self):
	#def __init__(self):
		# clearing variables and setting up the log counters
		# --===========================================--
		self.log['lineCount'] = 0
		self.log['newCount'] = 0
		self.log['dupeCount'] = 0
		self.log['startTime'] = datetime.now()
		self.log['endTime'] = ""
		self.log['sqlEntries'] = 0
		self.log['SQLErrorCount'] = 0
		# self.threatLibrary = threatResults.copy()
		# --===========================================--
		self.createFileString(self)

	# end constructor

	def extractFromDB(self):

		print ("Connecting to SQLite DB for extracting IOCs...")
		con = _sqlite3.connect('../../../Threats.sqlite')
		cursor = con.cursor()
		sqlString = "SELECT * FROM 'RecordedThreatsDB' ;" 
		sqlResult = cursor.execute(sqlString)

		# iterate through each row/entry for the resturned query, using description to fetch key names
		self.threatList = [dict(zip([key[0] for key in cursor.description],row)) for row in sqlResult]
		for item in self.threatList:
			tempKey = item.get('threatKey')
			self.threatDict[tempKey] = item
		# for x in range(0,2):
		# 	item = self.threatList[x]
		# 	tempKey = item.get('threatKey')
		# 	self.threatDict[tempKey] = item

	# Method to create a unique file name for exported information
	def createFileString(self):
		self.fileString = 'TIMS_Export_' + datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

	# CSV File Write Method
	def writeCSV(self,writeLoc):
		if writeLoc.endswith('/') == False:
			writeLoc = writeLoc + '/'
		fileString = writeLoc + self.fileString + '.csv'
		print("Writing CSV File: " + fileString)
		# with open(fileString,'wb') as outfile:
		keys = self.threatList[0].keys()
		with open(fileString, 'w') as output_file:
			dict_writer = csv.DictWriter(output_file,keys)
			dict_writer.writeheader()
			dict_writer.writerows(self.threatList)

	#JSON File Write Method
	def writeJSON(self,writeLoc):
		if writeLoc.endswith('/') == False:
			writeLoc = writeLoc + '/'
		fileString = writeLoc + self.fileString + '.json'
		print("Writing JSON File: " + fileString)

		with open(fileString,'w') as output_file:
			json.dump(self.threatDict,output_file)

	def recordStats(self):

		self.log['endTime']= datetime.now()
		print ("-- ============================ --")
		print("Total Entries:" + str( self.log['lineCount']))
		print ("New Entries:" + str( self.log['newCount']))
		print("Duplicates:" + str( self.log['dupeCount']))
		print("Start Time:" + str( self.log['startTime']))
		print("End Time:" + str( self.log['endTime']) )
		print ("Total Time Spent:" + str (self.log['endTime'] - self.log['startTime']))

		sg.Popup("Import Finished",
				 "Total Entries: " + str( self.log['lineCount']),
				 "New Entries: " + str( self.log['newCount']),
				 "Duplicates: " + str(self.log['dupeCount']),
				 "Start Time:" + str(self.log['startTime']),
				 "End Time:" + str(self.log['endTime']),
				 "Total Time Spent:" + str(self.log['endTime'] - self.log['startTime']))



		con = _sqlite3.connect('../../Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
		cursor = con.cursor()
		cursor.execute("INSERT INTO ThreatStatsDB VALUES (?,?,?,?,?,?)",
					   [self.log['lineCount'],
						self.log['newCount'],
						self.log['dupeCount'],
						str(self.log['startTime']),
						str(self.log['endTime']),
						str((self.log['endTime'] - self.log['startTime']))
						])
		print ("committing to Logging DB")
		con.commit()
	# END show stats

if __name__ == '__main__':
	exportObj = SQL_Export
	exportObj.__init__(exportObj)
	exportObj.extractFromDB(exportObj)
	print(exportObj.fileString)
	exportObj.writeCSV(exportObj,'/Users/Scott/Downloads')
	exportObj.writeJSON(exportObj,'/Users/Scott/Downloads')
