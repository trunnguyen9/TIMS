from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.after_request
def after_request(response):
  response.headers.add('Access-Control-Allow-Origin', '*')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
  return response

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