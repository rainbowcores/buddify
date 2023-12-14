from flask import Flask, Blueprint, make_response, jsonify, request, Blueprint, abort, json, redirect, session
from flask.logging import create_logger
from .firebase import db
import os
import requests
from urllib.parse import urlencode
import base64

app = Flask(__name__)
log = create_logger(app)

auth = Blueprint('auth', __name__, url_prefix='/auth')
client_id = os.getenv("client_id")
redirect_uri = os.getenv("redirect_uri")
scope = os.getenv("scope")
client_secret = os.getenv("client_secret")
tokenUrl = 'https://accounts.spotify.com/api/token'


@auth.route('/login', methods=['GET'])
def login():
	state = os.urandom(16).hex()
	authorize_url = 'https://accounts.spotify.com/authorize?response_type=code&client_id='+client_id+'&redirect_uri='+redirect_uri+'&scope='+scope +\
		'&show_dialog=false&state='+state
	login_response = redirect(authorize_url)
	print('logged in')
	return login_response


@auth.route('/callback', methods=['GET'])
def callback():
	code = request.args.get("code")
	error = request.args.get("error")
	'''In both cases, your app should compare the state parameter that it received in the redirection URI with the state parameter it originally provided to Spotify in the authorization URI. If there is a mismatch then your app should reject the request and stop the authentication flow.'''
	if code is None and error is not None:
		print(error)
		log.error('callback:' + str(error))
		return redirect('/error')
	else:
		return getInitToken(code)
	
def response(code, message, data=None):
	""" Creates a basic reposnse """
	response = {
		"status": code,
		"message": message,
		"data": data
	}
	return make_response(jsonify(response), code)


def saveDataToSession(post_response):

	if post_response.status_code == 200:
		pr = post_response.json()
		session['access_token'] = pr['access_token']
		if pr['refresh_token'] != None:
			session['refresh_token'] = pr['refresh_token']
		session['expires_in'] = pr['expires_in']
		getCurrentUser()
		return response(post_response.status_code, 'Token gotten sucessfully', pr)
	elif post_response.status_code == 400:
		return redirect('/error')
	else:
		log.error('gettingToken:' + str(post_response) + '\n session' + str(session))
		return redirect('/error')


def saveUserDetailsToDB(current_user_details, **kwargs):
	if ("shared_user_details" in kwargs):
		shared_user_details = kwargs['shared_user_details']
		doc_ref = db.collection(u'users').document(
			u''+shared_user_details['user_id'])
		doc_ref.set({
			u'user': u''+shared_user_details['user_id'],
			u'access_token': u''+current_user_details['access_token'],
			u'refresh_token': u''+shared_user_details['refresh_token']
		})
	else:
		session['user_id'] = current_user_details['id']
		doc_ref = db.collection(u'users').document(u''+session['user_id'])
		doc_ref.set({
			u'user': u''+session['user_id'],
			u'access_token': u''+session['access_token'],
			u'refresh_token': u''+session['refresh_token']
		})
	return response(200, 'User Details saved to db')


def getLoginStatus():
	if 'access_key' not in session:
		return redirect('/auth/login')


def getInitToken(code):
	headers = {'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
			'Authorization': 'Basic ' + base64.b64encode((client_id + ':' + client_secret).encode('utf-8')).decode('utf-8')}
	body = {'code': code, 'redirect_uri': redirect_uri,
	    'grant_type': 'authorization_code'}
	return getToken(body, headers)


def getToken(body, headers):
	post_response = requests.post(tokenUrl, headers=headers, data=body)
	log.error(body)
	log.error(headers)
	log.error(post_response)
	return saveDataToSession(post_response)


def refreshToken(session):
	body = {'refresh_token': session['refresh_token'],
         'grant_type': 'refresh_token'}
	headers = {'Authorization': 'Basic ' + base64.b64encode((client_id + ':' + client_secret).encode('utf-8')).decode('utf-8')}
	return getToken(body, headers)


def makeGetRequest(session, url, params={}):
	if 'access_token' not in session:
		return None
	else:
		headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded',
				"Authorization": "Bearer {}".format(session['access_token'])}
		request_response = requests.get(url, headers=headers, params=params)
	if request_response.status_code == 200:
			return request_response
	elif request_response.status_code == 401:
		refreshToken(session)
		request_response = makeGetRequest(session, url, params)
		return request_response.json()
	else:
		log.error('makeGetRequest Failed: ' +
					str(request_response.status_code) + ' url: ' + str(url))
		return response(request_response.status_code, 'url: ' + str(url), request_response)


@auth.route('/currentUser', methods=['GET'])
def getCurrentUserView():
	getLoginStatus()
	return getCurrentUser()


def getCurrentUser():
	current_user_details = makeGetRequest(
		session, 'https://api.spotify.com/v1/me', )
	if current_user_details is None:
		return redirect('/auth/login')
	# return current_user_details.json()
	return saveUserDetailsToDB(current_user_details.json())


@auth.route('/shareProfile')
def shareProfile():
	getLoginStatus()
	return response(200, 'Shared User Profile Successfully', request.url_root+'user/'+session['user_id'])


def getSharedUserDetails(username):
	user_details = db.collection(u'users').document(u''+username)
	get_user_details = user_details.get(
		field_paths={'user', 'access_token', 'refresh_token'}).to_dict()
	# user=get_bal.get('user')
	shared_user_details = {}
	shared_user_details['user_id'] = get_user_details.get('user')
	shared_user_details['access_token'] = get_user_details.get('access_token')
	shared_user_details['refresh_token'] = get_user_details.get('refresh_token')
	return shared_user_details


@auth.route('/user/<username>')
def sharedUserHomePage(username):
	return redirect('/')
