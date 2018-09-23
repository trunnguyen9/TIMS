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
from datetime import datetime
import _sqlite3

class DataEnricher:

	recordedThreats = dict()
	sqlDBloc = '../../../Threats.sqlite'

	def __init__(self):
		#Collect current time to update database with
		modtime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
	# end extractFromDB

	def updateDB(self):
		currentDateTime = datetime.now()
		con = _sqlite3.connect(self.sqlDBloc)
		cursor= con.cursor()

		progressBarTicker = 0
		for item in self.recordedThreats:
			sqlString = ["UPDATE RecordedThreatsDB SET"] 
			sqlString.append("'lastTime' = " + str(currentDateTime))
			sqlString.append(",'enriched' = 1")
			sqlString.append(",'gps' = " + self.recordedThreats[item]['gps'])
			sqlString.append(" WHERE 'threatKey' = " + self.recordedThreats[item]['threatKey'] + ";")
			# print("".join(sqlString))
			# cursor.execute(sqlString)
    # end updateDB

if __name__ == '__main__':
	test = DataEnricher()
	test.__init__()
	test.extractFromDB()
	# test.displayExtract()
	test.updateDB()






