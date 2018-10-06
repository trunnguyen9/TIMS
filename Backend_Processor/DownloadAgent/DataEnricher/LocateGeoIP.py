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

<<<<<<< HEAD
from ExportAgent import DataEnricher
=======
from .DataEnricher import DataEnricher
>>>>>>> origin/angularsql
import geoip2.database
# from datetime import datetime
# import _sqlite3

class LocateGeoIP(DataEnricher):

	asnDBloc = ''
	cityDBloc = ''
	countryDBloc = ''

	def __init__(self):
		# Connect the GeoLite object to all available databases of interest
		self.asnDBloc = './GeoLite2/GeoLite2-ASN_20180918/GeoLite2-ASN.mmdb'
		self.cityDBloc = './GeoLite2/GeoLite2-City_20180911/GeoLite2-City.mmdb'
		self.countryDBloc = './GeoLite2/GeoLite2-Country_20180911/GeoLite2-Country.mmdb'

	def searchASN(self):
		# Connect to the Database
		print('Connecting to GeoIP Autonomous System Database...')
		reader = geoip2.database.Reader(self.asnDBloc)
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()
		# Iterate through each threat
		print('Locating IP Adresses Autonomous System Details...')
		for item in self.recordedThreats:
			try:
				response = reader.asn(self.recordedThreats[item]['indicator'])
				self.recordedThreats[item]['asn'] = response.autonomous_system_number
				self.recordedThreats[item]['asn_desc'] = response.autonomous_system_organization
				self.recordedThreats[item]['Enriched'] = 1
			except:
				self.recordedThreats[item]['asn'] = ''
				self.recordedThreats[item]['asn_desc'] = ''
				pass
		reader.close()

	def searchCity(self):
		# Connect to the Database
		print('Connecting to GeoIP City Database...')
		reader = geoip2.database.Reader(self.cityDBloc)
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()
		# Iterate through each threat
		print('Locating IP Adresses City of Origin...')
		for item in self.recordedThreats:
			try:
				response = reader.city(self.recordedThreats[item]['indicator'])
				self.recordedThreats[item]['gps'] = [response.location.latitude,response.location.longitude]
				self.recordedThreats[item]['country_iso'] = response.country.iso_code
				self.recordedThreats[item]['country_name'] = response.country.name
				self.recordedThreats[item]['city_name'] = response.city.name
				self.recordedThreats[item]['postal_code'] = response.postal.code
				self.recordedThreats[item]['Enriched'] = 1
			except:
				self.recordedThreats[item]['gps'] = ''
				self.recordedThreats[item]['country_iso'] = ''
				self.recordedThreats[item]['country_name'] = ''
				self.recordedThreats[item]['city_name'] = ''
				self.recordedThreats[item]['postal_code'] = ''
				pass
		reader.close()
			# self.recordedThreats[item]['asn'] = [response.location.latitude,response.location.latitude]

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
	test.__init__()
	test.searchCity()
	test.searchASN()
	test.updateDB()
	# test.displayExtract()
	# test.updateDB()




