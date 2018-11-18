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
# from DataStore_Modules import *
from modules import *
from UnitTest import Test_ExportModule,Test_IoT,Test_IoT_All

# Create a UnitTest Loader to discover test names/TestCase
loader = unittest.TestLoader()
print("")
print("===================== BEGIN IoT UNIT TESTS =====================")
print("")
# Set up a suite to house tests
suite  = unittest.TestSuite()

# Extract Tests from TestCases
suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_AlienVault))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_EmergingThreats))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_Feodotracker))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_CSIRTG))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_NetLabs360))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_NoThink))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_OpenPhish))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_PhishTank))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_SANsEDU))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_SpamHaus))
#suite.addTests(loader.loadTestsFromTestCase(Test_IoT_All.Test_IoT_Zeus))

# Run All Test Cases
runner = unittest.TextTestRunner(verbosity=3)
result = runner.run(suite)
print("====================== END IoT UNIT TESTS ======================")
print("")
print("")
print("================ BEGIN EXPORT MODULE UNIT TESTS ================")
# Set up a suite to house tests
suite  = unittest.TestSuite()

# Extract Tests from TestCases
suite.addTests(loader.loadTestsFromTestCase(Test_ExportModule))

# Run All Test Cases
runner = unittest.TextTestRunner(verbosity=3)
result = runner.run(suite)
print("================= END EXPORT MODULE UNIT TESTS =================")




