from flask import Flask, Blueprint, make_response, jsonify, request, Blueprint, abort, json, redirect, session
from flask.logging import create_logger
import os
import requests
app = Flask(__name__)
log = create_logger(app)

thisapi = Blueprint('thisapi', __name__, url_prefix='/api')
client_id = os.getenv("client_id")
redirect_uri = os.getenv("redirect_uri")
scope = os.getenv("scope")
client_secret = os.getenv("client_secret")



@thisapi.route('/login', methods=['GET'])
def login():

    authorize_url = 'https://accounts.spotify.com/en/authorize?response_type=code&client_id='+client_id+'&redirect_uri='+redirect_uri+'&scope='+scope+\
    '&show_dialog=false'
    # query_params = url_encode(params)
    my_response = redirect(authorize_url)

    print('logged in2')
    return my_response


@thisapi.route('/callback', methods=['GET'])
def callback():
    code = request.args.get("code")
    error = request.args.get("error")
    if code is None and error is not None:
        print(error)
        log.error('callback:' + str(error))
        return redirect('/error')
    else:
        return getInitToken(code)

@thisapi.route('/currentUser', methods=['GET'])
def getCurrentUser() :
    return makeGetRequest(session, 'https://api.spotify.com/v1/me', )

def response(code, message, data=None):
    """ Creates a basic reposnse """
    response = {
        "status": code,
        "message": message,
        "data": data
    }
    return make_response(jsonify(response), code)

def getInitToken(code):
    body = {'code': code, 'redirect_uri': redirect_uri, 'grant_type': 'authorization_code', 'client_id': client_id,
    'client_secret': client_secret}
    return getToken(body)

def getToken(body):
    token_url = 'https://accounts.spotify.com/api/token'
    headers = {'Accept': 'application/json','Content-Type': 'application/x-www-form-urlencoded'}
    post_response = requests.post(token_url, headers=headers, data=body)

    if post_response.status_code == 200:
        pr = post_response.json()
        #pr['access_token'], pr['refresh_token'], pr['expires_in']
        session['access_token']=pr['access_token']
        session['refresh_token']=pr['refresh_token']
        session['expires_in']=pr['expires_in']
        print(pr)
        return response (post_response.status_code, 'Token gotten sucessfully', pr)
    else:
        # print (repr(post_response))
        log.error('gettingToken:' + str(body))
        # return jsonify({'you sent ':some_json})
        # some_json=request.get_json()
        return post_response.json()


def refreshToken(refresh_token):
    body = {'grant_type': 'refresh_token','refresh_token':refresh_token, 'client_id': client_id}
    return getToken(body)

def makeGetRequest(session, url, params={}):
  headers = {"Authorization": "Bearer {}".format(session['access_token'])}
  request_response = requests.get(url, headers=headers, params=params)
  if request_response.status_code == 200:
    return request_response.json()
  elif request_response.status_code == 401:
    checkTokenStatus(session)
    return makeGetRequest(session, url, params)
  else:
    log.error('makeGetRequest: ' + str(request_response.status_code) + ' url: '+ str(url))
    return response(request_response.status_code, 'url: '+ str(url), request_response)

def checkTokenStatus(session):
    return refreshToken(session['refresh_token'])  
    
