from flask import Flask, Blueprint, make_response, jsonify, request, Blueprint, abort, json, redirect, session
from flask_session import Session
from flask.logging import create_logger
import os
import requests
from app.auth import (getCurrentUser, response, getInitToken, getToken, refreshToken, makeGetRequest, checkTokenStatus,\
thisapi,client_id, redirect_uri, scope, client_secret)

app = Flask(__name__)
log = create_logger(app)