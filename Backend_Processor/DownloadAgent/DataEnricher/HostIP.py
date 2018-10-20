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
from multiprocessing import Pool, Queue
import socket
import requests

class HostIP(DataEnricher):

	keyList = []
	count = 0
	count_total = 0

	def __init__(self):
		super().__init__()
		# If there is no data in the dictionary, extract it
		self.sqlString += "WHERE 'indicator' NOT LIKE" + '\''  + ' %' + 'IP:' + '% ' + '\''
		if not self.recordedThreats:
			self.extractFromDB() 
		# # Restrict Number of Tests
		# tmp = dict();
		# keys = list(self.recordedThreats.keys())
		# for count in range(100):
		# 	tmp[keys[count]] = self.recordedThreats[keys[count]]
		# self.recordedThreats = tmp

	def searchHostname(self,item):
		# Indicate Change in Entry
		address = 'IP:'
		try: 
			# Search hostname name for IP address
			response = socket.gethostbyname(self.recordedThreats[item]['indicator'])
			if not response:
				print_str = ' - nReturn'
			else:
				print_str = ' - Success'
				# Update Data Entry
				address += response
		except: 
			print_str = ' - Failure'
		return [item,address,print_str]

	def getIP_standard(self):
		# Set Counter
		self.count = 0
		self.count_total = len(self.recordedThreats)
		# Iterate through each threat
		print('Retrieving IP Addresses from Hostname Indicators...')
		# Iterate through dictionary
		for item in self.recordedThreats:
			# Submit Entry Indicator
			ip = self.searchHostname(item)
			# Update Counter
			self.count = self.count + 1
			# Print Result to Screen
			self.print_line('Entry: ' + ip[0] + ' | #' + str(self.count) + '/' + str(self.count_total) + ip[2])
			# Update Database
			if self.recordedThreats[ip[0]]['rData'].find('IP:') == -1:
				self.recordedThreats[ip[0]]['rData'] = self.recordedThreats[ip[0]]['rData'] + ip[1]
		print('\n')


	def getIP_threaded(self):
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()

		# Set Counter
		self.count = 0
		self.count_total = len(self.recordedThreats)

		# Set up Multiprocessing Pool
		num_proc = 100
		pool = Pool(processes=num_proc)
		queue = Queue()

		# Construct Key List
		self.keyList = []
		for item in self.recordedThreats:
			# Append Key to Processes List
			self.keyList.append(item)

		# Call the processing pool to execute the function
		for ip in pool.imap_unordered(self.searchHostname,self.keyList):
			# Update Counter
			self.count = self.count + 1
			# Print Result to Screen
			self.print_line('Entry: ' + ip[0] + ' | #' + str(self.count) + '/' + str(self.count_total) + ip[2])
			# Update Database
			if self.recordedThreats[ip[0]]['rData'].find('IP:') == -1:
				self.recordedThreats[ip[0]]['rData'] = self.recordedThreats[ip[0]]['rData'] + ip[1]

		pool.close()
		pool.join()
		print('\n')

	def displayExtract(self):
		for item in self.recordedThreats:
			try:
				print(self.recordedThreats[item]['rData'])
			except:
				pass


if __name__ == '__main__':
	test = HostIP()
	test.getIP_threaded()
	test.updateDB()
	# test.displayExtract()
	# test.getIP_standard()
	




