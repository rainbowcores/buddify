"""app initializer """
import os
from flask import Flask
import app.auth
from app.auth import auth

config_name = os.getenv("APP_SETTINGS")

app = Flask(config_name)
app.secret_key = os.getenv("SECRET")
# """you import this to get all that we had defined and exported in the .env"""
# """this is imported from the __init__.py file contained in the subdirectory called app"""

# """Gets the app settings defined in the .env file"""

# app = create_app(config_name)

# """defining the configuration to be used"""


app.register_blueprint(auth)




@app.route('/')
def hello():
    """home"""
    return 'Welcome to Buddify'

@app.route('/error')
def error():
    """error"""
    return 'Error Authorizing Spotify'


if __name__ == '__main__':
    app.run()
