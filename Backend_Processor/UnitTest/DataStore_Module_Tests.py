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

import unittest
from Backend_Processor.DownloadAgent.DataStore_Modules import DataStore_Internal #Import PhishTank IoC
from Backend_Processor.DownloadAgent.DataStore_Modules import DataStore_SQLite #Import PhishTank IoC


class DataStore_Module_UnitTests(unittest.TestCase)

	# /*
	# Example Test Format
	# #Test -- Not Corrected From Java
	# def  ExampleTest(){
	#  // This test should pass
	#  Assert.assertTrue(1==1)
	# }

	# #Test -- Not Corrected From Java
	# def  ExampleTest2(){
	#  // This test should fail
	#  Assert.assertTrue(1==0)
	# }
	#  */

	#Test -- Not Corrected From Java
	def  AddResourceToListOfMonitoredResources(self):
		existingList = GetExistingList()
		itemToAdd = dict()
		updatedList = HGMMethods.AddItem(existingList, itemToAdd)
		Assert.assertTrue(updatedList.contains(itemToAdd))

	#Test -- Not Corrected From Java
	def  CollectingResourceTest(self):
		uri = 'http://data.phishtank.com/data/online-valid.json'
		result = HGMMethods.CreateHTTPRequest(uri)
		Assert.assertTrue(result.contains("HTTP POST"))


	#Test -- Not Corrected From Java
	def  ParseANewResourceTest(self):
		String uri = "www.examplelocation.com/textthreatexample"
		HGMObject importedHgmObject = HGMMethods.ImportFromURI(uri)
		Assert.assertTrue(importedHgmObject.HGMType = HGMType.Text)


	#Test -- Not Corrected From Java
	def  AddThreatToDatabaseTest(self):
		String uri = "www.examplelocation.com/databasethreatexample"
		MockDatabase mockDatabase = new MockDatabase()
		ArrayList<HGMObject> importResult = HGMMethods.Import(uri, mockDatabase)
		Assert.assertTrue(importResult.element.sourceReference == uri)


	#Test
	def  ViewThreatsTest(self):
		threats = self.getThreats()
		self.assertTrue(threats.get(1).getClass() instanceof IoC_PhishTank)


	#Test -- Not Corrected From Java
	def  ExportThreadListTest(self):
		ArrayList<HGMObject> threats = HGMMethods.GetThreatList()
		ArrayList<String> exportedThreats = HGMMethods.ExportThreatlistToType(threats, HGMType.Text)
		Assert.assertTrue(exportedThreats.get(1) instanceof String)


	#Test -- Not Corrected From Java
	def  UserAuthenticationTest(self):
		HGMUser hgmUser = HGMMethods.AuthenticateUser(username, password)
		Assert.assertTrue(hgmUser.userType == HGMUserType.User)

		HGMUser hgmAdmin = HGMMethods.AuthenticateUser(admin, adminPassword)
		Assert.assertTrue(hgmAdmin.userType == HGMUserType.Admin)


	#Test -- Not Corrected From Java
	def  UserAuthorizationTest(self):
		HGMUser hgmUser = HGMMethods.AuthenticateUser(username, password)
		Assert.assertFalse(HGMMethods.CanDeleteDatabase(hgmUser))

		HGMUser hgmAdmin = HGMMethods.AuthenticateUser(admin, adminPassword)
		Assert.assertTrue(HGMMethods.CanDeleteDatabase(hgmUser))


	#Test -- Not Corrected From Java
	def  ChangePasswordTest(self): 
		HGMMethods.ChangePassword(username, newPassword)
		Assert.assertTrue(HGMMethods.getPassword(hgmUser) == newPassword)


	#Test -- Not Corrected From Java
	def  ResetPasswordTest(self):
		HGMMethods.ResetPassword(username)
		Assert.assertFalse(HGMMethods.getPassword(hgmUser) == oldPassword)


	#Test -- Not Corrected From Java
	def  SearchAThreat(self):
		ThreatList = HGMMethods.SearchAThreat(keyword)
		Assert.assertTrue(ThreatList == ExpectedThreatList)


	#Test -- Not Corrected From Java
	def  ConfigurationFileGenerationTest(self):
		HGMPreferences hgmPreferences = HGMUIObject.getPreferences()
		Assert.assertTrue(HGMPreferences instanceof Document)


	#Test -- Not Corrected From Java
	def  OutputOptionsTest(self):
		ArrayList<HGMObject> threats = HGMMethods.GetThreatList()
		ArrayList<String> exportedCSVThreats = HGMMethods.ExportThreatlistToType(threats, HGMType.CSV)
		Assert.assertTrue(exportedCSVThreats.get(1) instanceof HGMType.CSV)

		ArrayList<String> exportedTSVThreats = HGMMethods.ExportThreatlistToType(threats, HGMType.TSV)
		Assert.assertTrue(exportedTSVThreats.get(1) instanceof HGMType.TSV)

		ArrayList<String> exportedJSONThreats = HGMMethods.ExportThreatlistToType(threats, HGMType.JSON)
		Assert.assertTrue(exportedJSONThreats.get(1) instanceof HGMType.JSON)

		ArrayList<String> exportedBroThreats = HGMMethods.ExportThreatlistToType(threats, HGMType.Bro)
		Assert.assertTrue(exportedBroThreats.get(1) instanceof HGMType.Bro)

		ArrayList<String> exportedSnortThreats = HGMMethods.ExportThreatlistToType(threats, HGMType.Snort)
		Assert.assertTrue(exportedSnortThreats.get(1) instanceof HGMType.Snort)

if __name__ == '__main__':
    unittest.main()