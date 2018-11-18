# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# simple methods used for exporting data from SQLlite database
# Darrell Was Here!

from pprint import pprint
from datetime import datetime
import os
import _sqlite3
import json
import csv
import socket

# import FrontEnd_GUI
# import PySimpleGUI as sg

class ExportSQL:
	threatList = []
	threatDict = dict()
	fileString = ''
	sqlDBloc = '../Database/Threats.sqlite'
	sqlTableName = 'RecordedThreatsDB'
	sqlString = "SELECT * FROM "

	def __init__(self, writeLoc):
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
				self.sqlString = self.sqlString + ";"
				# print(self.sqlString)
				sqlResult = cursor.execute(self.sqlString)

				# iterate through each row/entry for the resturned query, using description to fetch key names
				self.threatList = [dict(zip([key[0] for key in cursor.description], row)) for row in sqlResult]
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
			with open(fileString, 'w', encoding='utf8') as output_file:
				dict_writer = csv.DictWriter(output_file, keys)
				dict_writer.writeheader()
				dict_writer.writerows(self.threatList)
		else:
			print("No information was successfully extracted for writing")

	# end csv write method

	# CSV File Write Method
	def writeTab(self):
		if self.threatList:
			fileString = self.fileString + '.txt'
			print("Writing Tab Text File: " + fileString)
			# with open(fileString,'wb') as outfile:
			keys = self.threatList[0].keys()
			with open(fileString, 'w', encoding='utf8') as output_file:
				dict_writer = csv.DictWriter(output_file, keys, delimiter='\t')
				dict_writer.writeheader()
				dict_writer.writerows(self.threatList)
		else:
			print("No information was successfully extracted for writing")

	# end csv write method

	def writeBro(self):
		# -- info on bro intelligence framework format --
		# -- fields:  (tab between fields) --
		# indicator     indicator_type    meta.source     meta.desc       meta.url
		#
		# -- indicator types: --
		# Intel::ADDR
		# Intel::SUBNET
		# Intel::URL
		# Intel::SOFTWARE
		# Intel::EMAIL
		# Intel::DOMAIN
		# Intel::USER_NAME
		# Intel::CERT_HASH (SHA1 HASH)
		# Intel::PUBKEY_HASH (MD5 HASH)
		# Intel::FILE_HASH (GENERIC HASH)
		# Intel::FILE_NAME
		#
		# -- Relationships to Database Fields: --
		# indicator <-> indicator
		# Indicator_type -> itype
		#       ipv4 -> Intel::ADDR
		#       ipv6 -> Intel::ADDR
		#       fqdn -> Intel::DOMAIN
		#       url -> Intel::URL
		#       email -> Intel::EMAIL
		#       cidr -> Intel::SUBNET
		#       md5 -> Intel::PUBKEY_HASH
		#       sha1 -> Intel::CERT_HASH
		#
		# meta.source <-> provider
		# meta.desc <-> description + tags
		# meta.url <-> provider + rdata (maybe?)
		#

		if self.threatList:
			# Add file extension
			fileString = self.fileString + '.bro'
			# Set header string
			hdrString = '#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\n'

			#Create itype conversion lists
			sql_itype = ['ipv4','ipv6','fdnq',\
						'url','email','cidr',\
						'md5','sha1']
			bro_itype = ['Intel::ADDR','Intel::ADDR','Intel::DOMAIN',\
						'Intel::URL','Intel::EMAIL','Intel::SUBNET',\
						'Intel::PUBKEY_HASH','Intel::CERT_HASH']

			# Set up dictionary keys to extract as a list of lists
			fields = []
			fields.append(['indicator'])
			fields.append(['iType'])
			fields.append(['provider'])
			fields.append(['description','tags'])
			fields.append(['provider','rData'])

			wkeys = ['indicator','indicator_type','meta.source','meta.desc','meta.url']

			#Construct a list of new dictionaries to write to the file
			writeList = []
			#Iterate through all entires in the dictionary
			for threat in self.threatList:
				tmp = dict()
				#Iterate through fields list for writing data to bro format
				for k in range(0,len(fields)):
					line = []
					for key in fields[k]:
						#Extract Dictionary Entires of Interest
						line.append(str(threat[key]))
						# If iType field, replace with approriate string
						if 'iType' in key:
							for i in range(0,len(sql_itype)-1):
								line = [w.replace(sql_itype[i],bro_itype[i]) for w in line]
					# Set entry in writing dictionary and update list				
					tmp[wkeys[k]] = ', '.join(line)
				writeList.append(tmp)

			with open(fileString, 'w', encoding='utf8') as output_file:
				# Write all valyes of the dictionary to the file
				print("Writing BRO File: " + fileString)
				# # Write Field Names to the File
				output_file.write(hdrString)
				# Call dictionary writer
				dict_writer = csv.DictWriter(output_file,fieldnames=wkeys,delimiter='\t')
				dict_writer.writerows(writeList)
		else:
			print("No information was successfully extracted for writing")

	def writeSNORT(self):
		# If no data in the threat list, return error
		if self.threatList:
			# Add file extension
			fileString = self.fileString + '.snort'

			# Create an list for containing Snort rules
			writeList = []
			# Start signature ID number
			sid = 999999;

			# Iterate through threat list
			for item in self.threatList:
				# Assume flag should not be written
				writeFlag = 0
				# Set the sections of the snort rule as a list
				# [action,protocol,IP,Port,Direction,IP,Port,start action]
				write = ['alert','TCP','any','any','->','any','any','(']
				
				# Check the indicator was an IPv4 address, if so update rule
				if self.is_valid_ipv4_address(item['indicator']) == True: 
					write[5] = item['indicator']
					# write[6] = 'none'
					writeFlag = 1
				# Check the indicator was an IPv6 address, if so update rule
				elif self.is_valid_ipv6_address(item['indicator']) == True: 
					write[5] = item['indicator']
					# write[6] = 'none'
					writeFlag = 1
				# Otherwise check if the hostIP enrichment located an IP address
				else:
					address = item['rData']
					if address.find('IP:') != -1:
						# Attempt to parse the IP from the rData field
						address = address.split('IP:',1);
						if len(address[1]) < 12:
							address = address[1][0:len(address)-1]
						else:
							address = address[1]
						# If address is vald
						if address:
							write[5] = address
							# write[6] = 'none'
							writeFlag = 1

				# If write list has been updated, add to list
				if writeFlag == 1:
					# Update Rule Signature ID
					sid = sid + 1

					# References Rule
					if item['iType'] == 'url':
						write.append('reference:url,' + item['indicator'] + ';')
						writeFlag = 1

					# Priority Rule
					if item['tlp'] == 'green':
						write.append('priority: 1;')
					else:
						write.append('priority: 0;')

					# Threashold Rule
					write.append('threshold: type limit,track by_src,count 1,seconds 3600;')

					# SID Rule
					write.append('sid: ' +str(sid) + ';')

					# msg rule
					key_list = ['provider','tlp','tags','description']
					action_list = ['msg:"']
					for key in key_list:
						if item[key]:
							action_list.append(str(item[key]) + ' - ')
					if len(action_list) == 1:
						action_list.append('General Threat')
					# Construct MSG string
					msg = ''.join(action_list)
					msg = msg[:-3] +  '";'
					write.append(msg)

					# Close snort actions
					write.append(')\n')
					writeList.append(' '.join(write))

			# Open File
			with open(fileString, 'w', encoding='utf8') as output_file:
				print("Writing SNORT File: " + fileString)
				# Write all rules to file
				for item in writeList:
					output_file.write(item)
		else:
			print("No information was successfully extracted for writing")
	

	# JSON File Write Method
	def writeJSON(self):
		if self.threatDict:
			fileString = self.fileString + '.json'
			print("Writing JSON File: " + fileString)
			with open(fileString, 'w', encoding='utf8') as output_file:
				json.dump(self.threatDict, output_file)
		else:
			print("No information was successfully extracted for writing")

	# end json write method

	def addValues(self, colName, valueList):
		# Check to see if a where clause already exists, if not add it
		if 'WHERE' not in self.sqlString:
			self.sqlString += " WHERE "
		else:
			self.sqlString += " OR "
		# Add the column name to parse through and start the acceptable list
		if colName not in self.sqlString:
			self.sqlString += "  " + colName + " IN ("
		# Iterate through all list items and add to list
		for item in valueList:
			# print(type(item))
			self.sqlString += '\'' + item + '\','
		# Remove final comma from string
		if self.sqlString.endswith(','):
			self.sqlString = self.sqlString[:-1]
		# Close List Parenthesies
		self.sqlString += ")"

	# Getter Methods
	def copyDict(self):
		return self.threatDict

	def copyDBloc(self):
		return self.sqlDBloc

	def copyDBname(self):
		return self.sqlTableName

	# Setter Methods
	def updateDBloc(self, newLoc):
		self.sqlDBloc = newLoc + '/' + os.path.split(self.sqlDBloc)[1]
		self.sqlDBloc.replace('//', '/')
		print('Database Location Updated to: ' + self.sqlDBloc)

	def updateTablename(self, newName):
		self.sqlString.replace(self.sqlTableName, newName)
		self.sqlTableName = newName
		print('Table Name Updated to: ' + self.sqlTableName)

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

# if __name__ == '__main__':
# 	exportObj = ExportSQL('./')
# 	exportObj.extractFromDB()
	# exportObj.writeCSV()
	# exportObj.writeTab()
	# exportObj.writeJSON()
	# exportObj.writeBro()
	# exportObj.writeSNORT()

