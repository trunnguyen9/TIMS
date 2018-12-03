from flask import Flask, request, jsonify
import json
from ExportAgent import ExportThreatStats, ExportRecordedThreats
from UserStore_Module import UserStore
from flask import send_file, request
import logging
import jwt

app = Flask(__name__)

handler = logging.FileHandler('app.log')
handler.setLevel(logging.ERROR)

@app.after_request
def after_request(response):
  response.headers.add('Access-Control-Allow-Origin', '*')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
  return response

def __init__(self):
    pass

@app.route('/getConfig', methods=['GET'])
def getConfig():
    if not isValidToken():
        return jsonify({"Error": "Token is not valid. Please login again!"}), 403
    else:
        return jsonify(getConfigData()), 200

@app.route('/updateConfig',methods=['PUT'])
def updateConfig():
    if not isValidToken():
        return jsonify({"Error": "Token is not valid. Please login again!"}), 403
    else:
        content = request.get_json()
        updateConfigFile(content)
        return jsonify(content), 201

def updateConfigFile(content):
    with open('config.json', 'w+') as configFile:
        configFile.write(json.dumps(content, indent=4, sort_keys=True))
        configFile.close()

def getConfigData():
    with open('config.json', 'r') as configFile:
        data = json.load(configFile)
        configFile.close()
    return data

@app.route('/users/authenticate',methods=['POST'])
def authenticate():
    userStoreInstance = UserStore()
    data = request.get_json()
    msg = userStoreInstance.retrieveUser(data['username'], data['password'] )
    json.dumps(msg)
    return jsonify(msg), 200

@app.route('/users/register',methods=['POST'])
def createUser():
    userStoreInstance = UserStore()
    data = request.get_json()
    msg = userStoreInstance.createUser(data['firstName'], data['lastName'], data['username'], data['password'])
    return jsonify(msg), 200
@app.route('/users/<userid>',methods=['PUT'])
def updateUser(userid):
    userStoreInstance = UserStore()
    data = request.get_json()
    if not isValidToken():
        return jsonify({"Error": "Token is not valid. Please login again!"}), 403
    else:
        msg = userStoreInstance.updateUser(userid, data['oldPassword'], data['newPassword'])
        return jsonify(msg), 200

@app.route('/statisticByProvider',methods=['GET'])
def statisticByProvider():
    if not isValidToken():
        return jsonify({"Error": "Token is not valid. Please login again!"}), 403
    else:
        exportThreatStatInstance = ExportRecordedThreats()
        return exportThreatStatInstance.exportRTStatisticByProvider()

@app.route('/dump',methods=['GET'])
def dumpDatabase():
    if not isValidToken():
        return jsonify({"Error": "Token is not valid. Please login again!"}), 403
    else:
        exportThreatStatInstance = ExportThreatStats()
        return exportThreatStatInstance.exportThreatStats()

@app.route('/download/<path>')
def downloadFile (path = None):
    if not isValidToken():
        return jsonify({"Error": "Token is not valid. Please login again!"}), 403
    else:
        if path is None:
            self.Error(400)
        try:
            return send_file('./ExportedFiles/' + path, as_attachment=True)
        except Exception as e:
            self.log.exception(e)
            self.Error(400)

def isValidToken():
    token = request.headers.get('Authorization')
    if not token:
        return False
    try:
        decoded = jwt.decode(token, 'secret', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
    return True

app.logger.addHandler(handler)