from flask import Flask,session
from flask_session import Session
from app.auth import auth
from app.playlist import playlist

from instance.config import app_config

def create_app(config_name):
    app = Flask(__name__)
    Session(app)
    sess = Session()
    app.config.from_object(app_config[config_name])
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SECRET_KEY'] = 'redsfsfsfsfis'
    sess.init_app(app)
    app.app_context().push()
    app.register_blueprint(auth)
    app.register_blueprint(playlist)
    #app.config.from_pyfile('config.py')
    print("init")

    return app