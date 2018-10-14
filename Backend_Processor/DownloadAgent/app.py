from flask import Flask, request, jsonify
import json
from ExportAgent import ExportThreatStats
from UserStore_Module import UserStore
import jwt

app = Flask(__name__)

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

@app.route('/dump',methods=['GET'])
def dumpDatabase():
    exportThreatStatInstance = ExportThreatStats()
    return exportThreatStatInstance.exportThreatStats()

@app.route('/users/authenticate',methods=['POST'])
def authenticate():
    userStoreInstance = UserStore()
    data = request.get_json()
    msg = userStoreInstance.retrieveUser(data['username'], data['password'] )
    if msg is None:
        return jsonify({'Error' : 'Username or password is incorrect'}), 200
    else:
        encoded = jwt.encode({'username': msg[1]}, 'secret', algorithm='HS256').decode('utf-8')
        user = {
            'id' : msg[0],
            'username': msg[1],
            'firstname': msg[2],
            'lastname': msg[3],
            'token': encoded
        }
        json.dumps(user)
        return jsonify(user), 200
