# for running app
from flask import Flask, session, request, redirect, url_for, make_response, jsonify
# for decorator
from functools import wraps
# for swagger ui
from flask_swagger_ui import get_swaggerui_blueprint
# contains token verification
from tokentest import *

app = Flask(__name__)
# app config
secret_key = 'my_secret_key'
app.config['SECRET_KEY'] = secret_key

# swagger config
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
SWAGGER_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name' : 'Bank Case Study API' 
    }
)
app.register_blueprint(SWAGGER_BLUEPRINT, url_prefix=SWAGGER_URL)

# testing variables
payload_data = {
    "username": "Jessica Temporal",
    "password": "JessPass"
}


# helper methods
def token_required(f):
    '''Decorator to authrnticate token when API call is made'''
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = request.headers.get('apikey', None)
            # return 404 if token is not passed
            if not token:
                return make_response(jsonify({'message' : 'Token not found !!'}), 404)
            # decoding the token to fetch the stored details
            data = Token.checkToken(bytes(token, 'utf-8'), secret_key)
            if "Jessica Temporal" != data['username']:
                return make_response(jsonify({'message' : 'Token is invalid !!'}), 401)
        except Exception as e:
            print(f'{e}')
            return make_response(jsonify({'message' : 'Could not verify token'}), 500)
        # proceed with functionality
        return  f(*args, **kwargs)
    return decorated


# application routes
@app.route('/')
def generateToken():
    '''Home page'''
    session['username'] = payload_data['username']
    session['token'] = Token.generateToken(payload_data, secret_key)
    return f"{session['token'].decode()}"


@app.route('/usersession/<some_val>', methods =['GET'])
def getUserSession(some_val):
    '''Test page to verify session token'''
    if Token.checkToken(session['token'], secret_key)['username'] == session['username']:
        return f"{some_val}"
    return f"No authorization."


@app.route('/clearsession')
def clearsession():
    '''Page to clear session variables'''
    session.pop('username', default=None)
    session.pop('token', default=None)
    return f"Cleared. Token is now {session.get('token', 'No token')}"


# API methods
@app.route('/api/retrievetoken', methods=['POST'])
def retrieveToken():
    '''Retrieve Token'''
    try:
        payload = request.get_json()
        username = payload.get('username', '')
        password = payload.get('password', '')
        if len(username) == 0 or len(password) == 0 or len(payload) > 2:
            print('Bad request')
            return make_response(jsonify({'token' : '', 
                                          'success' : False}), 400)
        token = Token.generateToken(payload, secret_key).decode()
        if len(token) == 0:
            return make_response(jsonify({'token' : token, 
                                          'success' : False}), 500)
        return make_response(jsonify({'token' : token, 
                                      'success' : True}), 200)
    except Exception as e:
        print(f'{e}')
        return make_response(jsonify({'token' : '', 
                                      'success' : False}), 500)


'''Verify Token'''
@app.route('/api/verifytoken', methods =['GET'])
@token_required
def getUserHeader():
    return make_response(jsonify({'message' : 'Token is valid !!'}), 200)


# error handling
@app.errorhandler(400)
def handle_400_error(_error):
    """Return a http 400 error to client"""
    return make_response(jsonify({'error': 'Misunderstood'}), 400)


@app.errorhandler(401)
def handle_401_error(_error):
    """Return a http 401 error to client"""
    return make_response(jsonify({'error': 'Unauthorised'}), 401)


@app.errorhandler(404)
def handle_404_error(_error):
    """Return a http 404 error to client"""
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.errorhandler(500)
def handle_500_error(_error):
    """Return a http 500 error to client"""
    return make_response(jsonify({'error': 'Server error'}), 500)


app.run(debug=True)