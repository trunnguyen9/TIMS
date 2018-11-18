from flask import Flask, request, jsonify
import json
from ExportAgent import ExportThreatStats, ExportRecordedThreats
from UserStore_Module import UserStore
from flask import send_file
import logging

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
    return jsonify(getConfigData()), 200

@app.route('/updateConfig',methods=['PUT'])
def updateConfig():
    if request.method == 'PUT':
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

@app.route('/statisticByProvider',methods=['GET'])
def statisticByProvider():
    exportThreatStatInstance = ExportRecordedThreats()
    return exportThreatStatInstance.exportRTStatisticByProvider()

@app.route('/dump',methods=['GET'])
def dumpDatabase():
    exportThreatStatInstance = ExportThreatStats()
    return exportThreatStatInstance.exportThreatStats()

@app.route('/download/<path>')
def downloadFile (path = None):
    if path is None:
        self.Error(400)
    try:
        return send_file('./ExportedFiles/' + path, as_attachment=True)
    except Exception as e:
        self.log.exception(e)
        self.Error(400)


app.logger.addHandler(handler)