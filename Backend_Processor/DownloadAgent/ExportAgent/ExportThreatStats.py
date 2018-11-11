import _sqlite3
import DataStore_Modules


def formatHtml(retRows):
    html = "<!DOCTYPE html>" \
           "<html>" \
           "<head>" \
           "<style>" \
           "table {" \
           "font-family: arial, sans-serif;" \
           "border-collapse: collapse;" \
           "width: 100%;" \
           "}" \
           "td, th {" \
           "border: 1px solid #dddddd;" \
           "text-align: left;" \
           "padding: 8px;" \
           "}" \
           "tr:nth-child(even) {" \
           "background-color: #dddddd;" \
           "}" \
           "</style>" \
           "</head>" \
           "<body>" \
           "<h2>Threat Statistics</h2>" \
           "<table>" \
           "  <tr>" \
           "<th>lineCount</th>" \
           "<th>newCount</th>" \
           "<th>dupeCount</th>" \
           "<th>startTime</th>" \
           "<th>endTime</th>" \
           "<th>timeSpent</th>" \
           "<th>provider</th>" \
           "<th>hostname</th>" \
           "  </tr>"
    for row in retRows:
        html += "<tr>"
        for item in row:
            html += "<td>" + str(item) + "</td>"
        html += "</tr>"
    html += "</table>" \
            "</body>" \
            "</html>"

    return html


class ExportThreatStats:
    sqlString = "SELECT * FROM ThreatStatsDB;"
    conn = 0
    sqlDBloc = './Threats.sqlite'

    def __init__(self):
        self.conn = _sqlite3.connect('./Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)

    def exportThreatStats(self):
        print("Connecting to SQLite DB for extracting ThreatStats")
        cursor = self.conn.cursor()
        sqlString = "SELECT * FROM ThreatStatsDB;"
        cursor.execute(sqlString)
        rows = cursor.fetchall()
        htmlRetString = formatHtml(rows)
        return htmlRetString
