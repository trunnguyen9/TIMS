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
import os
import _sqlite3
import json
import csv
# import FrontEnd_GUI
# import PySimpleGUI as sg

class ExportSQL:

	threatList = []
	threatDict = dict()
	fileString = ''
	sqlDBloc = os.getcwd() + '/Threats.sqlite'
	sqlTableName = 'RecordedThreatsDB'
	sqlString = "SELECT * FROM "

	def __init__(self,writeLoc):
		# Set Up SQL databse request
		print(self.sqlDBloc)
		self.sqlString = self.sqlString + self.sqlTableName
		# create a timestamp string to use when writing files
		self.fileString = writeLoc
		if self.fileString.endswith('/') == False:
			self.fileString = self.fileString + '/'
		self.fileString = self.fileString + 'TIMS_Export_' + datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

	# end constructor

	def extractFromDB(self):
		# Attempt to open a connection and verify that the database is there
			# print ("Connecting to SQLite Database...")
		print('Attempting to Connect to: ' + self.sqlDBloc)
		count = 0
		while not os.path.isfile(self.sqlDBloc) and count < 3:
			print('Database not found, searching up directory structure...')
			newLoc = os.path.split(self.sqlDBloc)[0]
			newLoc = os.path.split(newLoc)[0]
			self.updateDBloc(newLoc)
			count = count + 1;

		if os.path.isfile(self.sqlDBloc):
			con = _sqlite3.connect(self.sqlDBloc)
			print('Connected to: ' + self.sqlDBloc)
			cursor = con.cursor()
			try:
				self.sqlString = self.sqlString +  ";" 
				# print(self.sqlString)
				sqlResult = cursor.execute(self.sqlString)

				# iterate through each row/entry for the resturned query, using description to fetch key names
				self.threatList = [dict(zip([key[0] for key in cursor.description],row)) for row in sqlResult]
				for item in self.threatList:
					tempKey = item.get('threatKey')
					self.threatDict[tempKey] = item
			except:
				print('Table was not located in database, extract aborted')
			cursor.close()
			con.close()	
		else:
			print('Database File Could Not Be Located.')

	# CSV File Write Method
	def writeCSV(self):
		if self.threatList:
			fileString = self.fileString + '.csv'
			print("Writing CSV File: " + fileString)
			# with open(fileString,'wb') as outfile:
			keys = self.threatList[0].keys()
			with open(fileString, 'w') as output_file:
				dict_writer = csv.DictWriter(output_file,keys)
				dict_writer.writeheader()
				dict_writer.writerows(self.threatList)
		else:
			print("No information was successfully extracted for writing")
	#end csv write method

	#JSON File Write Method
	def writeJSON(self):
		if self.threatDict:
			fileString = self.fileString + '.json'
			print("Writing JSON File: " + fileString)
			with open(fileString,'w') as output_file:
				json.dump(self.threatDict,output_file)
		else:
			print("No information was successfully extracted for writing")
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

	# Getter Methods
	def copyDict(self):
		return self.threatDict

	def copyDBloc(self):
		return self.sqlDBloc

	def copyDBname(self):
		return self.sqlTableName

	# Setter Methods
	def updateDBloc(self,newLoc):
		self.sqlDBloc = newLoc + '/' + os.path.split(self.sqlDBloc)[1]
		self.sqlDBloc.replace('//','/')
		print('Database Location Updated to: ' + self.sqlDBloc)

	def updateTablename(self,newName):
		self.sqlString.replace(self.sqlTableName,newName)
		self.sqlTableName = newName
		print('Table Name Updated to: ' + self.sqlTableName)

if __name__ == '__main__':
	exportObj = ExportSQL('./')
	exportObj.extractFromDB()
	exportObj.writeCSV()
	exportObj.writeJSON()
