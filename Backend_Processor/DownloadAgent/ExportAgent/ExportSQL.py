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

class ExportSQL:

	threatList = []
	threatDict = dict()
	fileString = ''
	sqlString = "SELECT * FROM 'RecordedThreatsDB' "
	sqlDBloc = '../../../Threats.sqlite'

	def __init__(self,writeLoc):
		# create a timestamp string to use when writing files
		self.fileString = writeLoc
		if self.fileString.endswith('/') == False:
			self.fileString = self.fileString + '/'
		self.fileString = self.fileString + 'TIMS_Export_' + datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
	# end constructor

	def extractFromDB(self):
		print ("Connecting to SQLite DB for extracting IOCs...")
		con = _sqlite3.connect(self.sqlDBloc)
		cursor = con.cursor()
		self.sqlString = self.sqlString + ";" 
		print(self.sqlString)
		sqlResult = cursor.execute(self.sqlString)

		# iterate through each row/entry for the resturned query, using description to fetch key names
		self.threatList = [dict(zip([key[0] for key in cursor.description],row)) for row in sqlResult]
		for item in self.threatList:
			tempKey = item.get('threatKey')
			self.threatDict[tempKey] = item

	# CSV File Write Method
	def writeCSV(self):
		fileString = self.fileString + '.csv'
		print("Writing CSV File: " + fileString)
		# with open(fileString,'wb') as outfile:
		keys = self.threatList[0].keys()
		with open(fileString, 'w') as output_file:
			dict_writer = csv.DictWriter(output_file,keys)
			dict_writer.writeheader()
			dict_writer.writerows(self.threatList)
	#end csv write method

	#JSON File Write Method
	def writeJSON(self):
		fileString = self.fileString + '.json'
		print("Writing JSON File: " + fileString)
		with open(fileString,'w') as output_file:
			json.dump(self.threatDict,output_file)
	#end json write method

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

	def copyDict(self):
		return self.threatDict

	def updateDBloc(self,newLoc):
		self.sqlDBloc = newLoc


if __name__ == '__main__':
	exportObj = ExportSQL('/Users/Scott/Downloads')
	exportObj.addValues('tlp',['green'])
	exportObj.addValues('tags',['malware'])
	exportObj.extractFromDB()
	exportObj.writeCSV()
	exportObj.writeJSON()
