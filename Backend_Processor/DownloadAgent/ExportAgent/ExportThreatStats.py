import sqlite3
import DataStore_Modules

class ExportThreatStats:
    sqlString = "SELECT * FROM ThreatStatsDB;"
    conn = 0

    def __init__(self):
        sqliteDataStoreInstance = DataStore_Modules.DataStore_SQLite.SQLiteDataStore()
        self.conn = sqliteDataStoreInstance.getDBConn()

    def exportThreatStats(self):
        print("Connecting to SQLite DB for extracting ThreatStats")
        cursor = self.conn.cursor()
        sqlString = "SELECT * FROM ThreatStatsDB;"
        cursor.execute(sqlString)
        rows = cursor.fetchall()
        retString = ''.join(map(str,rows))
        return retString