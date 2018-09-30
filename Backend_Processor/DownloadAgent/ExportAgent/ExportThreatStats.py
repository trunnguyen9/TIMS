import _sqlite3

class ExportThreatStats:
    sqlString = "SELECT * FROM 'ThreatStatsDB' "
    sqlDBloc = '../../../Threats.sqlite'

    def __init__(self):{}

    def exportThreatStats(self):
        print("Connecting to SQLite DB for extracting ThreatStats")
        con = _sqlite3.connect(self.sqlDBloc)
        cursor = con.cursor()
        self.sqlString = self.sqlString + ";"
        print(self.sqlString)
        sqlResult = cursor.execute(self.sqlString)
        return sqlResult