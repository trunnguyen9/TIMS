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
from IoC_Modules import *
from UnitTest import *

# Create a UnitTest Loader to discover test names/TestCase
loader = unittest.TestLoader()

print("===================== BEGIN IoC UNIT TESTS =====================")
# Set up a suite to house tests
suite  = unittest.TestSuite()

# Extract Tests from TestCases
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_EmergingThreats))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_PhishTank))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_AlienVault))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_Feodotracker))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_CSIRTG))

# Run All Test Cases
runner = unittest.TextTestRunner(verbosity=3)
result = runner.run(suite)
print("====================== END IoC UNIT TESTS ======================")
print("")
print("")
print("==================== BEGIN EXPORT UNIT TESTS ====================")
# Set up a suite to house tests
suite  = unittest.TestSuite()

# Extract Tests from TestCases
suite.addTests(loader.loadTestsFromTestCase(Test_ExportModule))

# Run All Test Cases
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
print("===================== END EXPORT UNIT TESTS =====================")




