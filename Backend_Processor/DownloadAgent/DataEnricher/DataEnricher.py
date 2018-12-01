# --====================================================--
# Threat Information Management System (T.I.M.S.)
# Download Agent
# Group 2 - Fall 2018
# Darrell Miller, Doug Peck, Raymond Schmalzl, Trung Nguyen
#
# --====================================================--
#
# Baseline object to provide read and update capabilities 
# for data enrichment tools 
# 
from datetime import datetime
import _sqlite3
import sys
import os
import time
import socket
import elasticsearch
from elasticsearch import Elasticsearch


class DataEnricher:
    recordedThreats = dict()
    sqlDBloc = '../Database/Threats.sqlite'
    modtime = ''
    sqlString = "SELECT * FROM 'RecordedThreatsDB' "
    segment = 1000

    enrichLog = dict()
    breakCount = 0

    def __init__(self):
        # Collect current time to update database with
        self.modtime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.enrichLog['startTime'] = datetime.now()
        self.enrichLog['endTime'] = 0
        self.enrichLog['totalProcessed'] = 0
        self.enrichLog['totalSuccess'] = 0
        self.enrichLog['totalFailure'] = 0

    def set_sqlDBloc(self, newLoc):
        self.sqlDBloc = newLoc

    def copyExtract(self):
        return self.recordedThreats

    def displayExtract(self):
        for item in self.recordedThreats:
            print(self.recordedThreats[item])

    # Parent Enrich Data Method to be overwritten by sub classes
    def enrichData(self):
        pass

    # Parent Enrich Data Method to be overwritten by sub classes for threading
    def enrichData_threaded(self):
        pass

    def extractFromDB(self):
        # Attempt to open a connection and verify that the database is there
        print('Attempting to Connect to: ' + self.sqlDBloc)
        count = 0
        while not os.path.isfile(self.sqlDBloc) and count < 3:
            print('Database not found, searching up directory structure...')
            newLoc = os.path.split(self.sqlDBloc)[0]
            newLoc = os.path.split(newLoc)[0]
            self.set_sqlDBloc(newLoc)
            count = count + 1;
        # Construct SQL String
        self.sqlString = self.sqlString + ";"
        # Connect to SQL Database
        con = _sqlite3.connect(self.sqlDBloc)
        cursor = con.cursor()
        sqlResult = cursor.execute(self.sqlString)

        # iterate through each row/entry for the resturned query, using description to fetch key names
        threatList = [dict(zip([key[0] for key in cursor.description], row)) for row in sqlResult]
        for item in threatList:
            tempKey = item.get('threatKey')
            self.recordedThreats[tempKey] = item

        # Close the connection to the database
        con.commit()
        con.close()

    # end extractFromDB

    def updateDB(self):
        # Connect to the Threats Database
        con = _sqlite3.connect(self.sqlDBloc)
        cursor = con.cursor()

        # Construct SQL String to Get the First Line of the Database
        colNameString = "SELECT * FROM RecordedThreatsDB ORDER BY ROWID ASC LIMIT 1;"
        # Get the Existing Column Names
        pullResult = cursor.execute(colNameString)
        # iterate through each row/entry for the resturned query, using description to fetch key names
        threatList = [dict(zip([key[0] for key in cursor.description], row)) for row in pullResult]
        # Find the Existing Keys in the Database
        currentKeys = threatList[0].keys()

        # Begin SQL String
        updateString = "UPDATE 'RecordedThreatsDB' SET "
        # Make certain all dictionary entries have a column to be inserted into
        example_key = list(self.recordedThreats.keys())[0]
        for key in self.recordedThreats[example_key]:
            # Add Key to SQL Update String
            updateString += str(key) + "=?,"
            # If the Given Key is Not in the Current Database, Add it
            if not key in currentKeys:
                try:
                    cursor.execute("ALTER TABLE 'RecordedThreatsDB' ADD COLUMN " + key + " ;")
                except:
                    pass

        # Remove trailing comma and finish string
        updateString = updateString[:-1]
        updateString += " WHERE threatKey=? ;"

        # Construct a tuple to insert into the database
        entries = []
        # Iterate through threats
        for item in self.recordedThreats:
            params = []
            for key in self.recordedThreats[item]:
                try:
                    params.append(self.recordedThreats[item][key])
                except:
                    # If the first entry doesn't work try inserting a blank vaue
                    params.append('')
            params.append(item)
            entries.append(params)
        try:
            # Push Update SQL Requests
            print('Pushing Enrichment to Thereat Database...')
            self.breakCount += 1
            print(self.breakCount)
            cursor.executemany(updateString, entries)

            # Close the SQL Connection
            con.commit()
            con.close()

        except _sqlite3.OperationalError as e:  # if database is locked, wait a second and try again.
            print("stats wait, collision!")
            time.sleep(1)
            con.commit()

    # Method to break the recorded threats push into segments of a specific number
    def segmentPush(self):
        # If there is no data in the dictionary, extract it
        if not self.recordedThreats:
            self.extractFromDB()

        # Move compelte list of recorded threats to a different variable
        recordedThreats_all = self.recordedThreats
        self.recordedThreats = dict()

        # Add threats to the dictionary until segment length is met
        count = 0

        for key in recordedThreats_all:
            self.recordedThreats[key] = recordedThreats_all[key]
            count = count + 1
            # When segment length is reached
            if count == self.segment:
                # Enrich the data
                self.enrichData()
                # Push to the database
                self.updateDB()
                # Reset dictionary and counter
                self.recordedThreats = dict()
                count = 0
        # Push the last < segment entires to the table
        # Enrich the data
        self.enrichData()
        # Push to the database
        self.updateDB()

        # reset variable recordedThreats
        self.recordedThreats = recordedThreats_all

    # Method to break the recorded threats push into segments of a specific number
    def segmentPush_threaded(self):
        # If there is no data in the dictionary, extract it
        if not self.recordedThreats:
            self.extractFromDB()

        # Move compelte list of recorded threats to a different variable
        recordedThreats_all = self.recordedThreats
        self.recordedThreats = dict()

        # Add threats to the dictionary until segment length is met
        count = 0

        for key in recordedThreats_all:
            self.recordedThreats[key] = recordedThreats_all[key]
            count = count + 1
            # When segment length is reached
            if count == self.segment:
                # Enrich the data
                self.enrichData_threaded()
                # Push to the database
                self.updateDB()
                # Reset dictionary and counter
                self.recordedThreats = dict()
                count = 0
        # Push the last < segment entires to the table
        # Enrich the data
        self.enrichData()
        # Push to the database
        self.updateDB()

        # reset variable recordedThreats
        self.recordedThreats = recordedThreats_all

    def addValues(self, colName, valueList):
        # Check to see if a where clause already exists, if not add it
        if 'WHERE' not in self.sqlString:
            self.sqlString += " WHERE "
        else:
            self.sqlString += " OR "
        # Add the column name to parse through and start the acceptable list
        if colName not in self.sqlString:
            self.sqlString += "  " + colName + " in ("
        # Iterate through all list items and add to list
        for item in valueList:
            # print(type(item))
            self.sqlString += '\'' + item + '\','
        # Remove final comma from string
        if self.sqlString.endswith(','):
            self.sqlString = self.sqlString[:-1]
        # Close List Parenthesies
        self.sqlString += ")"

    def print_line(self, string):
        sys.stdout.flush()
        sys.stdout.write('\r' + string)

    # Method to Check if string is IPV4 IP address
    def is_valid_ipv4_address(self, address):
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:  # no inet_pton here, sorry
            return False
        except socket.error:  # not a valid address
            return False
        return True

    # Method to Check if string is IPV6 IP address
    def is_valid_ipv6_address(self, address):
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:  # not a valid address
            return False
        return True

    # end updateDB

    # Method to change segment number externaly
    def set_segment(self, number):
        self.segment = number

    def saveEnrichLog(self):
        self.enrichLog['endTime'] = datetime.now()
        self.enrichLog['timeProccessed'] = self.enrichLog['endTime'] - self.enrichLog['startTime']
        print("Enrichment Log:")
        print("--===============--")
        print(self.enrichLog)

        try:
            es = Elasticsearch([{'host': '173.253.201.243', 'port': 9200}])
        except Exception as ex:
            print("ES ERROR:", ex)

        try:
            es.index(index='timsenricher_index', doc_type='timsenrich_log', id=self.enrichLog['startTime'],
                     body=self.enrichLog)
        except elasticsearch.ElasticsearchException as es1:
            print("TL Error:" + es1)


if __name__ == '__main__':
    pass
# test = DataEnricher()
# test.extractFromDB()
# # test.displayExtract()
# test.updateDB()
