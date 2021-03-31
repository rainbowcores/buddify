from flask import Flask, Blueprint, make_response, jsonify, request, Blueprint, abort, json, redirect
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
    client_id = 'f51a68b8ba2a41ab82ec17d6e85bb3b0'
    redirect_uri = 'http://127.0.0.1:5000/'
    scope = 'user-read-private user-read-email'

    authorize_url = 'https://accounts.spotify.com/en/authorize?response_type=code&' + \
        'client_id='+client_id+'&redirect_uri='+redirect_uri+'&scope='+scope
    # query_params = url_encode(params)
    my_response = make_response(redirect(authorize_url))

    print('logged in')
    return my_response
