class dataStore_MySQL_Logger:
    def __init__(self):
        print ("Starting MySql Logger:")
    # END __init__

    def writeToLog(self, strFeedName,intThreatNumber, strNotes):
        con = _sqlite3.connect('../../Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)
        cursor = con.cursor()
        cursor.execute(sqlString)
        #print ("SQL:", sqlString)
        cnx.commit()  # move this outside
        cnx.close()
    #end writeToLog

    def buildLogSQLString(self,strFeedName,IntThreatNumber,strNotes):
        strSQLString="INSERT INTO `threatLogger` (`Provider`, `No_of_Threats`, `Notes`, `indexKey`) VALUES ('"
        strSQLString+=strFeedName+"','"
        strSQLString+=str(IntThreatNumber)+"','"
        strSQLString+=strNotes+"',CURRENT_TIMESTAMP)"
        #print (strSQLString)
        return strSQLString
    #end buildLogSqlString

#end class dataStore_MySql_Logger