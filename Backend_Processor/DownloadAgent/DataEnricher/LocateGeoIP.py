# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Object used to enrich data by associating IP's with GeoLocations 
# 
# This product includes GeoLite2 data created by MaxMind, available from
# <a href="http://www.maxmind.com">http://www.maxmind.com</a>.
from DataEnricher import DataEnricher
from datetime import datetime
from multiprocessing import Pool
import socket
import geoip2.database


class LocateGeoIP(DataEnricher):

	asnDBloc = ''
	cityDBloc = ''
	countryDBloc = ''
	keyList = []
	count = 0
	count_total = 0

	def __init__(self):
		super().__init__()
		# Connect the GeoLite object to all available databases of interest
		self.asnDBloc = './GeoLite2/GeoLite2-ASN_20180918/GeoLite2-ASN.mmdb'
		self.cityDBloc = './GeoLite2/GeoLite2-City_20180911/GeoLite2-City.mmdb'
		self.countryDBloc = './GeoLite2/GeoLite2-Country_20180911/GeoLite2-Country.mmdb'

		# Only Extract Values that are not enriched
		self.sqlString += "WHERE enriched=0"
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()
		# # Restrict Number of Tests
		# tmp = dict();
		# keys = list(self.recordedThreats.keys())
		# for count in range(100):
		# 	tmp[keys[count]] = self.recordedThreats[keys[count]]
		# self.recordedThreats = tmp

	def searchASN(self,item):
		# Search for IP address
		address = self.recordedThreats[item]['indicator'] 
		if self.is_valid_ipv4_address(address) != True and self.is_valid_ipv6_address(address) != True:
			address = self.recordedThreats[item]['rData']
			if address.find('IP:') != -1:
				address = address.split('IP:',1);
				if len(address[1]) < 12:
					address = address[1][0:len(address)-1]
				else:
					address = address[1]
		# Set Keys and List for Values
		keys = ['asn','asn_desc'] 
		# Attempt to Collect Values
		values = []
		try:
			response = self.reader.asn(address)
			values.append(str(response.autonomous_system_number))
			values.append(str(response.autonomous_system_organization))
			print_str = ' - Success'
		except:
			values.append('')
			values.append('')
			print_str = ' - Failure'
		# Return Data
		return [print_str,item,keys,values]

	def searchCity(self,item):
		# Search for IP address
		address = self.recordedThreats[item]['indicator'] 
		if self.is_valid_ipv4_address(address) != True or self.is_valid_ipv6_address(address) != True:
			address = self.recordedThreats[item]['rData']
			if address.find('IP:') != -1:
				address = address.split('IP:',1);
				if len(address[1]) < 12:
					address = address[1][0:len(address)-1]
				else:
					address = address[1]
		# Set Keys and List for Values
		keys = ['gps','country_iso','country_name','city_name','postal_code'] 
		# Attempt to Collect Values
		values = []
		try:
			response = self.reader.city(address)
			values.append(str(response.location.latitude)+','+str(response.location.longitude))
			values.append(str(response.country.iso_code))
			values.append(str(response.country.name))
			values.append(str(response.city.name))
			values.append(str(response.postal.code))
			print_str = ' - Success'
		except:
			values.append('')
			values.append('')
			values.append('')
			values.append('')
			values.append('')
			print_str = ' - Failure'
		# Return Data
		return [print_str,item,keys,values]

	def enrichData(self):
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()
		# Count the Total Number of Threats
		self.count_total = len(self.recordedThreats)

		# Connect to the ASN Database
		print('Connecting to GeoLite 2 Autonomous System Database...')
		self.reader = geoip2.database.Reader(self.asnDBloc)

		# Set Counter
		self.count = 0
		# Iterate through the dictionary
		for item in self.recordedThreats:
			# Submit Entry Indicator
			rtn = self.searchASN(item)
			# Update Counter
			self.count = self.count + 1
			# Print Result to Screen
			self.print_line('Entry: ' + rtn[1] + ' | #' + str(self.count) + '/' + str(self.count_total) + rtn[0])
			# print('Entry: ' + rtn[1] + ' | #' + str(self.count) + '/' + str(self.count_total) + rtn[0])
			# Update Database
			self.updateValues(rtn[1],rtn[2],rtn[3])
		print('\n')
		#Close the Reader
		self.reader.close()

		# Connect to the City Database
		print('Connecting to GeoIP City Database...\n')
		self.reader = geoip2.database.Reader(self.cityDBloc)

		# Set Counter
		self.count = 0
		# Iterate through the dictionary
		for item in self.recordedThreats:
			# Submit Entry Indicator
			rtn = self.searchCity(item)
			# Update Counter
			self.count = self.count + 1
			# Print Result to Screen
			self.print_line('Entry: ' + rtn[1] + ' | #' + str(self.count) + '/' + str(self.count_total) + rtn[0])
			# print('Entry: ' + rtn[1] + ' | #' + str(self.count) + '/' + str(self.count_total) + rtn[0])
			# Update Database
			self.updateValues(rtn[1],rtn[2],rtn[3])
		print('\n')
		#Close the Reader
		self.reader.close()


	def enrichData_threaded(self):
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()
		# Count the Total Number of Threats
		self.count_total = len(self.recordedThreats)
		# Construct Key List
		self.keyList = []
		for item in self.recordedThreats:
			# Append Key to Processes List
			self.keyList.append(item)

		# Connect to the ASN Database
		print('Connecting to GeoLite 2 Autonomous System Database...')
		# Set Counter
		self.count = 0
		self.reader = geoip2.database.Reader(self.asnDBloc)
		# Set up Multiprocessing Pool
		num_proc = 30
		pool = Pool(processes=num_proc)
		# Call the processing pool to execute the function
		for rtn in pool.imap_unordered(self.searchASN,self.keyList):
			# Update Counter
			self.count = self.count + 1
			# Print Result to Screen
			self.print_line('Entry: ' + rtn[1] + ' | #' + str(self.count) + '/' + str(self.count_total) + rtn[0])
			# print('Entry: ' + rtn[1] + ' | #' + str(self.count) + '/' + str(self.count_total) + rtn[0])
			# Update Database
			self.updateValues(rtn[1],rtn[2],rtn[3])
		# Close the Pool
		pool.close()
		# Wait for Processes to Finish
		pool.join()
		#Close the Readers
		self.reader.close()
		print('\n')

		# Connect to the City Database
		print('Connecting to GeoIP City Database...\n')
		# Set Counter
		self.count = 0
		self.reader = geoip2.database.Reader(self.cityDBloc)
		# Set up Multiprocessing Pool
		num_proc = 30
		pool = Pool(processes=num_proc)
		# Call the processing pool to execute the function
		for rtn in pool.imap_unordered(self.searchASN,self.keyList):
			# Update Counter
			self.count = self.count + 1
			# Print Result to Screen
			self.print_line('Entry: ' + rtn[1] + ' | #' + str(self.count) + '/' + str(self.count_total) + rtn[0])
			# print('Entry: ' + rtn[1] + ' | #' + str(self.count) + '/' + str(self.count_total) + rtn[0])
			# Update Database
			self.updateValues(rtn[1],rtn[2],rtn[3])
		# Close the Pool
		pool.close()
		# Wait for Processes to Finish
		pool.join()
		#Close the Readers
		self.reader.close()
		print('\n')

	def updateValues(self,item,keys,values):
		self.recordedThreats[item]['enriched'] = 1
		for i in range(len(keys)):
			try:
				self.recordedThreats[item][keys[i]] = values[i]
				# print('Update Success')
			except:
				self.recordedThreats[item][keys[i]] = ''
				# print('Update Failure')

	def displayExtract(self):
		for item in self.recordedThreats:
			try:
				print(self.recordedThreats[item]['city_name'],',',
					self.recordedThreats[item]['country_name'],'-',
					self.recordedThreats[item]['postal_code'],',',
					self.recordedThreats[item]['country_iso'],
					self.recordedThreats[item]['gps'],'-',
					self.recordedThreats[item]['asn_desc'],':',
					self.recordedThreats[item]['asn'])
			except:
				pass

	# Update Location of ASN database
	def set_asnDBloc(self,newLoc):
		self.asnDBloc = newLoc

	# Update Location of City Database
	def set_cityDBloc(self,newLoc):
		self.cityDBloc = newLoc

	# Update Location of Country Database
	def set_countryDBloc(self,newLoc):
		self.countryDBloc = newLoc
# 
if __name__ == '__main__':
	pass
	# test = LocateGeoIP()
	# test.segmentPush()




