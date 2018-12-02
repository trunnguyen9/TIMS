import _sqlite3
import jwt
from datetime import timedelta, datetime

class UserStore:
    conn = 0

    def __init__(self):
        self.conn = _sqlite3.connect('./Database/Threats.sqlite', detect_types=_sqlite3.PARSE_DECLTYPES)

    def retrieveUser(self, username, password):
        cursor = self.conn.cursor()
        sqlString = "SELECT id, username, firstname, lastname FROM `User` WHERE `username` = '" + username + "' AND `password` = '" + password + "';"
        try:
            cursor.execute(sqlString)
            self.conn.commit()
            msg = cursor.fetchone()
            if msg is None:
                return {'Error': 'username or password is incorrect'}
            encoded = jwt.encode({'username': msg[1], 'exp': datetime.utcnow() + timedelta(seconds=10)}, 'secret', algorithm='HS256').decode('utf-8')
            user = {
                'id': msg[0],
                'username': msg[1],
                'firstname': msg[2],
                'lastname': msg[3],
                'token': encoded
            }
        except _sqlite3.Error as er:
            return {'error': 'Error occurred in retrieve user.'}

        return user

    def createUser(self, firstname, lastname, username, password):
        cursor = self.conn.cursor()
        params = (username, firstname, lastname, password)
        sqlString = "INSERT INTO `User` (username, firstname, lastname, password) VALUES (?, ?, ?, ?)";
        try:
            cursor.execute(sqlString, params)
            self.conn.commit()
        except _sqlite3.Error as er:
            return {'error' : 'Error occurred in creating user.Please try another username.'}
        return { 'lastrowid' : cursor.lastrowid }