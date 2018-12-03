import json
import _sqlite3

class ExportRecordedThreats:
    conn = 0
    def __init__(self):
        self.conn = _sqlite3.connect('./Database/Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)

    def exportRTStatisticByProvider(self):
        cursor = self.conn.cursor()
        sqlString = "SELECT provider AS name, COUNT(provider) AS y FROM RecordedThreatsDB GROUP BY provider;"
        cursor.execute(sqlString)
        row_headers = [x[0] for x in cursor.description]
        rows = cursor.fetchall()
        json_data = []
        for result in rows:
            json_data.append(dict(zip(row_headers, result)))
        return json.dumps(json_data)

    def exportRTStatisticByThreat(self):
        cursor = self.conn.cursor()
        sqlString = "SELECT provider AS name, COUNT(provider) AS y FROM RecordedThreatsDB GROUP BY provider;"
        cursor.execute(sqlString)
        rows = cursor.fetchall()
        return json.dumps(rows)

    def exportRTStatisticByTags(self):
        cursor = self.conn.cursor()
        sqlString = "SELECT lower(tags) AS name, COUNT(lower(tags)) AS y FROM RecordedThreatsDB GROUP BY lower(tags);"
        cursor.execute(sqlString)
        rows = cursor.fetchall()
        return json.dumps(rows)