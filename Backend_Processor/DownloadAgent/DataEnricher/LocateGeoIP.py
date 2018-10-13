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
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()
		# Connect the GeoLite object to all available databases of interest
		self.asnDBloc = './GeoLite2/GeoLite2-ASN_20180918/GeoLite2-ASN.mmdb'
		self.cityDBloc = './GeoLite2/GeoLite2-City_20180911/GeoLite2-City.mmdb'
		self.countryDBloc = './GeoLite2/GeoLite2-Country_20180911/GeoLite2-Country.mmdb'

	def searchASN(self,item):
		address = self.recordedThreats[item]['indicator'] 
		if self.is_valid_ipv4_address(address) != True or self.is_valid_ipv6_address(address) != True:
			address = self.recordedThreats[item]['rData']
			if address.find('IP:') != -1:
				address = address.split('IP:',1);
				if len(address[1]) < 12:
					address = address[1][0:len(address)-1]
				else:
					address = address[1]
		try:
			response = self.asnreader.asn(address)
			self.recordedThreats[item]['asn'] = response.autonomous_system_number
			self.recordedThreats[item]['asn_desc'] = response.autonomous_system_organization
			self.recordedThreats[item]['Enriched'] = 1
			self.print_line('Entry: ' + item + ' | #' + str(self.count) + '/' + str(self.count_total) + ' - Failure')
		except:
			self.recordedThreats[item]['asn'] = ''
			self.recordedThreats[item]['asn_desc'] = ''
			self.print_line('Entry: ' + item + ' | #' + str(self.count) + '/' + str(self.count_total) + ' - Success')

	def searchCity(self,item):
		address = self.recordedThreats[item]['indicator'] 
		if self.is_valid_ipv4_address(address) != True or self.is_valid_ipv6_address(address) != True:
			address = self.recordedThreats[item]['rData']
			if address.find('IP:') != -1:
				address = address.split('IP:',1);
				if len(address) < 12:
					address = address[0:len(address)]
		try:
			
			response = self.cityreader.city(address)
			self.recordedThreats[item]['gps'] = [response.location.latitude,response.location.longitude]
			self.recordedThreats[item]['country_iso'] = response.country.iso_code
			self.recordedThreats[item]['country_name'] = response.country.name
			self.recordedThreats[item]['city_name'] = response.city.name
			self.recordedThreats[item]['postal_code'] = response.postal.code
			self.recordedThreats[item]['Enriched'] = 1
			self.print_line('Entry: ' + item + ' | #' + str(self.count) + '/' + str(self.count_total) + ' - Success')
		except:
			self.recordedThreats[item]['gps'] = ''
			self.recordedThreats[item]['country_iso'] = ''
			self.recordedThreats[item]['country_name'] = ''
			self.recordedThreats[item]['city_name'] = ''
			self.recordedThreats[item]['postal_code'] = ''
			self.print_line('Entry: ' + item + ' | #' + str(self.count) + '/' + str(self.count_total) + ' - Failure')

	def searchDB(self):
		print('Connecting to GeoLite 2 Autonomous System Database...')
		self.asnreader = geoip2.database.Reader(self.asnDBloc)
		print('Connecting to GeoIP City Database...\n')
		self.cityreader = geoip2.database.Reader(self.cityDBloc)

		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()

		# Set Counter
		self.count = 1
		self.count_total = len(self.recordedThreats)

		# Iterate through the dictionary
		for item in self.recordedThreats:
			self.searchASN(item)
			self.searchCity(item)
			self.count = self.count + 1

		#Close the Readers
		self.asnreader.close()
		self.cityreader.close()

	def searchDB_threaded(self):
		# Connect to the Database
		print('Connecting to GeoLite 2 Autonomous System Database...')
		self.asnreader = geoip2.database.Reader(self.asnDBloc)
		print('Connecting to GeoIP City Database...\n')
		self.cityreader = geoip2.database.Reader(self.cityDBloc)

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
			self.keyList.append(item)
			self.count = self.count + 1
			# When the Pool is full, run the processes
			if num_proc%self.count == 0:
				pool.map(self.searchASN,self.keyList)
				pool.map(self.searchCity,self.keyList)
				self.keyList = []

		#Close the Readers
		self.asnreader.close()
		self.cityreader.close()

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
	def updateDBloc_asn(self,newLoc):
		self.asnDBloc = newLoc

	# Update Location of City Database
	def updateDBloc_city(self,newLoc):
		self.cityDBloc = newLoc

	# Update Location of Country Database
	def updateDBloc_country(self,newLoc):
		self.countryDBloc = newLoc

if __name__ == '__main__':
	test = LocateGeoIP()
	test.searchDB_threaded()
	# test.searchDB()
	# test.updateDB()




