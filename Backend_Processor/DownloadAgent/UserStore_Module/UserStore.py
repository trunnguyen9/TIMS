import DataStore_Modules

class UserStore:
    conn = 0

    def __init__(self):
        sqliteDataStoreInstance = DataStore_Modules.DataStore_SQLite.SQLiteDataStore()
        self.conn = sqliteDataStoreInstance.getDBConn()

    def retrieveUser(self, username, password):
        cursor = self.conn.cursor()
        sqlString = "SELECT id, username, firstname, lastname FROM `User` WHERE `username` = '" + username + "' AND `password` = '" + password + "';"
        cursor.execute(sqlString)
        msg = cursor.fetchone()
        return msg
