from flask import Flask, Blueprint, make_response, jsonify, request, Blueprint, abort, json
app = Flask(__name__)

thisapi = Blueprint('thisapi', __name__, url_prefix='/api')

def response(code, message, data=None):
    """ Creates a basic reposnse """
    response = {
        "status": code,
        "message": message,
        "data": data
    }
    return make_response(jsonify(response), code)

@thisapi.route('/login', methods=['GET'])
def login():
    print('logged in')
    return response(201, "Logged In"
    )