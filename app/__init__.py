from flask import Flask
from app.auth import thisapi as users

from instance.config import app_config

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(app_config[config_name])
    app.app_context().push()
    app.register_blueprint(users)
    #app.config.from_pyfile('config.py')
    print("init")

    return app