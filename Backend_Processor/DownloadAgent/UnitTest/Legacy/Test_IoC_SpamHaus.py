# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Unit Test Object with methods for assessing functionality of
# TIMS SpamHaus Module

from UnitTest import Test_IoC
from IoC_Modules import IoC_SpamHaus #Import Emerging Threats IoC

class Test_IoC_SpamHaus(Test_IoC):

	def setUp(self):
		self.ThreatObject = IoC_SpamHaus(self.SQLiteDataStore.getDBConn())	

if __name__ == '__main__':
	unittest.main()

