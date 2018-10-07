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
import socket
# from datetime import datetime
# import _sqlite3

class HostIP(DataEnricher):

	def __init__(self):
		super().__init__()
		pass	

	def getIP(self):
		# If there is no data in the dictionary, extract it
		if not self.recordedThreats:
			self.extractFromDB()
		count = 1
		count_total = len(self.recordedThreats)
		# Iterate through each threat
		print('Retrieving IP Addresses from Hostname Indicators...')
		for item in self.recordedThreats:
			self.print_line('Updating Entry: ' + str(count) + '/' + str(count_total))
			count = count + 1
			# Collect Entry Indicator
			hostname = self.recordedThreats[item]['indicator']
			# If the indicator is already an IP address, skip entry
			if count < 100:
				if is_valid_ipv4_address(hostname) != True and is_valid_ipv6_address(hostname) !=True:
					try:
						# Searhc host name for IP address
						response = socket.gethostbyname(hostname)
						# print('Hostname: ' + hostname + ' has IP: ' + response)
						# If no IP is returned, do not change the indicator
						if not response:
							pass
						else:
							self.recordedThreats[item]['indicator'] = response
							# print('Hostname: ' + hostname + ' has IP: ' + response)
					except: 
						# print('Get IP failed')
						pass
			# else:
				# print('Indicator is IP:' + hostname)
		self.print_line('')

# Method to Check if string is IPV4 IP address
def is_valid_ipv4_address(address):
	try:
		socket.inet_pton(socket.AF_INET, address)
	except AttributeError:  # no inet_pton here, sorry
		return False
	except socket.error:  # not a valid address
		return False
	return True

# Method to Check if string is IPV6 IP address
def is_valid_ipv6_address(address):
	try:
		socket.inet_pton(socket.AF_INET6, address)
	except socket.error:  # not a valid address
		return False
	return True

if __name__ == '__main__':
	test = HostIP()
	test.getIP()
	test.updateDB()




