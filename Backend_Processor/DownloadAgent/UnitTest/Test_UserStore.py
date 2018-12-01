# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Unit Tests for User Store Module Classes
# 
import unittest
import os
import _sqlite3
from UserStore_Module import *


class Test_UserStore(unittest.TestCase):

	def test_createUser(self):
		# Create User
		user_dict = self.user.createUser(self.test_fn,self.test_ln,self.test_un,self.test_pw)
		# Remove new Entry
		self.clear_entry()
		# Check for Return Error
		self.assertTrue('error' not in user_dict)


	def test_retrieveUser(self):
		# Create User
		create_user = self.user.createUser(self.test_fn,self.test_ln,self.test_un,self.test_pw)
		# Attempt to Locate the User
		user_dict = self.user.retrieveUser(self.test_un,self.test_pw)
		# Remove new Entry
		self.clear_entry()
		# Check for Return Error
		self.assertTrue('error' not in user_dict)

	def clear_entry(self):
		sqlString = "DELETE FROM 'User' WHERE username = " + '\'' + self.test_un + '\'' + " AND " + '\'' + self.test_pw + '\'' " ;"
		# Delete the inserted entry to avoid creating a security flaw
		conn = _sqlite3.connect('./Database/Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
		cursor = conn.cursor()
		cursor.execute(sqlString)
		conn.commit()
		cursor.close()
		conn.close()

	def setUp(self):
		self.user = UserStore()
		self.test_un = 'UnitTest_UserName'
		self.test_pw = 'UnitTest_Password'
		self.test_fn = 'UnitTest_FirstName'
		self.test_ln = 'UnitTest_LastName'






