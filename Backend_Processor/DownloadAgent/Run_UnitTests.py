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
from DataStore_Modules import *
from IoC_Modules import *
from UnitTest import *

# Create a UnitTest Loader to discover test names/TestCase
loader = unittest.TestLoader()
# Set up a suite to house tests
suite  = unittest.TestSuite()

# Extract Tests from TestCases
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_EmergingThreats))
suite.addTests(loader.loadTestsFromTestCase(Test_IoC_PhishTank))

# Run All Test Cases
runner = unittest.TextTestRunner(verbosity=3)
result = runner.run(suite)



