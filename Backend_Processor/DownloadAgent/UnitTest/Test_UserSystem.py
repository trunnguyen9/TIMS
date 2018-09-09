# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Unit Test Object with methods for assessing functionality of
# TIMS User System Modules

import unittest
from Backend_Processor.DownloadAgent.DataStore_Modules import DataStore_Internal #Import PhishTank IoC
from Backend_Processor.DownloadAgent.DataStore_Modules import DataStore_SQLite #Import PhishTank IoC

class UserSystem_UnitTests(unittest.TestCase)

	#Test -- Not Corrected From Java
	def  UserAuthenticationTest(self):
		HGMUser hgmUser = HGMMethods.AuthenticateUser(username, password)
		self.assertTrue(hgmUser.userType == HGMUserType.User)

		HGMUser hgmAdmin = HGMMethods.AuthenticateUser(admin, adminPassword)
		self.assertTrue(hgmAdmin.userType == HGMUserType.Admin)


	#Test -- Not Corrected From Java
	def  UserAuthorizationTest(self):
		HGMUser hgmUser = HGMMethods.AuthenticateUser(username, password)
		self.assertFalse(HGMMethods.CanDeleteDatabase(hgmUser))

		HGMUser hgmAdmin = HGMMethods.AuthenticateUser(admin, adminPassword)
		self.assertTrue(HGMMethods.CanDeleteDatabase(hgmUser))


	#Test -- Not Corrected From Java
	def  ChangePasswordTest(self): 
		HGMMethods.ChangePassword(username, newPassword)
		self.assertTrue(HGMMethods.getPassword(hgmUser) == newPassword)


	#Test -- Not Corrected From Java
	def  ResetPasswordTest(self):
		HGMMethods.ResetPassword(username)
		self.assertFalse(HGMMethods.getPassword(hgmUser) == oldPassword)


if __name__ == '__main__':
 unittest.main()