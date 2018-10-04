import _sqlite3

class ExportThreatStats:
    sqlString = "SELECT * FROM ThreatStatsDB"
    #sqlString = "SELECT * FROM RecordedThreatsDB"
    sqlDBloc = '../../Threats.sqlite'

    def __init__(self):
        self = self

    def exportThreatStats(self):
        print("Connecting to SQLite DB for extracting ThreatStats")
        con = _sqlite3.connect(self.sqlDBloc)
        cursor = con.cursor()
        self.sqlString = self.sqlString + ";"
        cursor.execute(self.sqlString)
        rows = cursor.fetchall()
        retString = ''.join(map(str,rows))
        return retString