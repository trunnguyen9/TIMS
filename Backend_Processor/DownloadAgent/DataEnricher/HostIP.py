# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Object used to enrich data by associating Hostnames with
# IP Addresses
# 
from DataEnricher import DataEnricher
from datetime import datetime
from multiprocessing import Pool
import socket
import requests

class HostIP(DataEnricher):

	keyList = []
	count = 0
	count_total = 0

	def __init__(self):
		super().__init__()
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()   

	def searchHostname(self,item):
		# Indicate Change in Entry
		self.count = self.count + 1
		try: 
			# Search hostname name for IP address
			response = socket.gethostbyname(self.recordedThreats[item]['indicator'])
			if not response:
				self.print_line('Entry: ' + item + ' | #' + str(self.count) + '/' + str(self.count_total) + ' - nReturn')
			else:
				# Update Data Entry
				self.recordedThreats[item]['rData'] = self.recordedThreats[item]['rData'] + 'IP:' + response
				self.print_line('Entry: ' + item + ' | #' + str(self.count) + '/' + str(self.count_total) + ' - Success')
		except: 
			self.print_line('Entry: ' + item + ' | #' + str(self.count) + '/' + str(self.count_total) + ' - Failure')

	def getIP_standard(self):
		self.count = 1
		self.count_total = len(self.recordedThreats)
		# Iterate through each threat
		print('Retrieving IP Addresses from Hostname Indicators...')
		# Iterate through dictionary
		for item in self.recordedThreats:
			# Submit Entry Indicator
			self.searchHostname(item)

	def getIP_threaded(self):
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()

		# Set Counter
		self.count = 1
		self.count_total = len(self.recordedThreats)

		# Set up Multiprocessing Pool
		num_proc = 15
		pool = Pool(processes=num_proc)

		# Iterate through all keys
		self.keyList = []
		for item in self.recordedThreats:
			# Append Key to Processes List
			self.keyList.append(item)
			# When the Pool is full, run the processes
			if self.count%num_proc == 0:
				pool.map(self.searchHostname,self.keyList)
				self.keyList = []

	def displayExtract(self):
		for item in self.recordedThreats:
			try:
				print(self.recordedThreats[item]['rData'])
			except:
				pass


if __name__ == '__main__':
	test = HostIP()
	test.getIP_threaded()
	# test.displayExtract()
	# test.getIP_standard()
	# test.updateDB()




