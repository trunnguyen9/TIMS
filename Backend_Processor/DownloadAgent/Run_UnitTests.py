# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Basic Run Script to Execute unite tests for defined test cases

import unittest
import nose
# from DataStore_Modules import *
from modules import *
from UnitTest import *

# Create a UnitTest Loader to discover test names/TestCase
loader = unittest.TestLoader()
print("")
print("================ BEGIN EXPORT MODULE UNIT TESTS ================")
# Set up a suite to house tests
suite  = unittest.TestSuite()

# Extract Tests from TestCases
suite.addTests(loader.loadTestsFromTestCase(Test_ExportModule))

# Run All Test Cases
runner = unittest.TextTestRunner(buffer=True,verbosity=2)
result = runner.run(suite)
print("================= END EXPORT MODULE UNIT TESTS =================")
print("")
print("================ BEGIN ENRICHMENT MODULE UNIT TESTS ================")
# Set up a suite to house tests
suite  = unittest.TestSuite()

# Extract Tests from TestCases
suite.addTests(loader.loadTestsFromTestCase(Test_DataEnricher))
suite.addTests(loader.loadTestsFromTestCase(Test_HostIP))
suite.addTests(loader.loadTestsFromTestCase(Test_LocateGeoIP))

# Run All Test Cases
runner = unittest.TextTestRunner(buffer=True,verbosity=2)
result = runner.run(suite)
print("================= END ENRICHMENT MODULE UNIT TESTS =================")
print("")
print("================ BEGIN USERSTORE MODULE UNIT TESTS ================")
# Set up a suite to house tests
suite  = unittest.TestSuite()

# Extract Tests from TestCases
suite.addTests(loader.loadTestsFromTestCase(Test_UserStore))

# Run All Test Cases
runner = unittest.TextTestRunner(buffer=True,verbosity=2)
result = runner.run(suite)
print("================= END USERSTORE MODULE UNIT TESTS =================")
print("")
print("===================== BEGIN IoC UNIT TESTS =====================")
# Set up a suite to house tests
suite  = unittest.TestSuite()

# Extract Tests from TestCases
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_AlienVault))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_EmergingThreats))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_Feodotracker))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_NetLabs360))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_NoThink))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_OpenPhish))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_PhishTank))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_SANsEDU))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_SpamHaus))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_All.Test_IoC_Zeus))			

# Run All Test Cases
runner = unittest.TextTestRunner(buffer=True,verbosity=2)
result = runner.run(suite)
print("====================== END IoC UNIT TESTS ======================")

