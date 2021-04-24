from flask import Flask, Blueprint, make_response, jsonify, request, Blueprint, abort, json, redirect, session
from flask_session import Session
from flask.logging import create_logger
import os
import requests
from app.auth import (getCurrentUser, response, saveUserDetailsToDB, refreshTokenHeaders, token_url,
					  client_id, redirect_uri, scope, client_secret, getSharedUserDetails, db)

app = Flask(__name__)
log = create_logger(app)

playlist = Blueprint('playlist', __name__, url_prefix='/api')

def refreshSharedUserToken(shared_user_details):
	body = {'refresh_token': shared_user_details['refresh_token'], 'grant_type': 'refresh_token'}
	headers = refreshTokenHeaders()
	post_response = requests.post(token_url, headers=headers, data=body)
	if post_response.status_code == 200:
		current_user_auth_details = post_response.json()
		log.info(shared_user_details)
		saveUserDetailsToDB(current_user_auth_details, shared_user_details=shared_user_details)
		return response(post_response.status_code, 'Token gotten resucessfully', current_user_auth_details)
	elif post_response.status_code == 400:
		return redirect('/api/login')
	else:
		log.error('gettingToken:' + str(post_response)+ '\n session' + str(session))
		return redirect('/api/login')

def makeSharedUserGetRequest(username, url, params={}):
	shared_user_details = getSharedUserDetails(username)
	headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded',
			   "Authorization": "Bearer {}".format(shared_user_details['access_token'])}
	request_response = requests.get(url, headers=headers, params=params)
	if request_response.status_code == 200:
		return request_response.json()
	elif request_response.status_code == 401:
		refreshSharedUserToken(shared_user_details)
		return makeSharedUserGetRequest(username, url, params)
	else:
		log.error('makeSharedUserGetRequest Failed: ' +
				  str(request_response.status_code) + ' url: ' + str(url))
		return response(request_response.status_code, 'url: ' + str(url), request_response)

@playlist.route('<username>/playlists', methods=['GET', 'POST'])
def getUserPlaylists(username):
	if request.method == 'GET':
		offset = request.args.get('offset', default=0, type=int)
		limit = request.args.get('limit', default=20, type=int)
		params = {'limit': limit, 'offset': offset}
		request_response = makeSharedUserGetRequest(
			username, 'https://api.spotify.com/v1/me/playlists', params)
		return response(200, 'Successfully gotten User Playlists', request_response)
	if request.method == 'POST':
		data = request.get_json()
		playlist_id = data['playlist_id']
		url = 'https://api.spotify.com/v1/playlists/'+playlist_id
		return makeSharedUserGetRequest(username, url, )

@playlist.route('<username>/playlist/new', methods=['POST'])
def getNewPlaylistData(username):
	data = request.get_json()
	body = json.dumps(data, indent = 4)
	return createNewPlaylist(body, username)

def createNewPlaylist(body, username):
	shared_user_details = getSharedUserDetails(username)
	headers = {'Content-Type': 'application/json',
			   "Authorization": "Bearer {}".format(shared_user_details['access_token'])}
	url = 'https://api.spotify.com/v1/users/'+username+'/playlists'
	post_response = requests.post(url, headers=headers, data=body)
	if post_response.status_code == 200 or post_response.status_code == 201:
		pr = post_response.json()
		return response(post_response.status_code, 'Playlist added sucessfully', pr)
	else:
		log.error('Add Playlist Failed: ' +
				  str(post_response.status_code) + ' url: ' + str(url))
		return response(post_response.status_code, 'url: ' + str(url), post_response)

@playlist.route('<username>/playlist/<playlist_id>', methods=['POST'])
def getAddItemToPlaylistData(username,playlist_id):
	data = request.get_json()
	body = json.dumps(data, indent = 4)
	return addItemToPlaylistData(username,playlist_id, body)

def addItemToPlaylistData(username,playlist_id, body):
	shared_user_details = getSharedUserDetails(username)
	headers = {'Content-Type': 'application/json',
			   "Authorization": "Bearer {}".format(shared_user_details['access_token'])}
	url = 'https://api.spotify.com/v1/playlists/'+playlist_id+'/tracks'
	post_response = requests.post(url, headers=headers, data=body)
	if post_response.status_code == 200 or post_response.status_code == 201:
		pr = post_response.json()
		return response(post_response.status_code, 'Item added sucessfully to playlist', pr)
	else:
		log.error('Add Item To Playlist Failed: ' +
				  str(post_response.status_code) + ' url: ' + str(url))
		return response(post_response.status_code, 'url: ' + str(url), post_response)
