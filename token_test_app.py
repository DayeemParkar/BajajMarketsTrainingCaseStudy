from flask import Flask, session, request, redirect, url_for, make_response
from datetime import datetime, timedelta
from functools import wraps

from tokentest import *

app = Flask(__name__)
# configuration
# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
secret_key = 'my_secret_key'
app.config['SECRET_KEY'] = secret_key
payload_data = {
    "sub": "4242",
    "name": "Jessica Temporal",
    "pass": "JessPass"
}


# for token in header
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('apikey', None)
        # return 401 if token is not passed
        if not token:
            return f"{ request.headers }", 401
  
        # decoding the payload to fetch the stored details
        data = Token.checkToken(bytes(token, 'utf-8'), secret_key)
        if "Jessica Temporal" != data['name']:
            return f"{ {'message' : 'Token is invalid !!'} }", 401
        # proceed with functionality
        return  f(*args, **kwargs)
  
    return decorated


@app.route('/')
def generateToken():
    session['username'] = payload_data['name']
    session['token'] = Token.generateToken(payload_data, secret_key)
    return f"{session['token'].decode()}"


@app.route('/userheader', methods =['GET'])
@token_required
def getUserHeader():
    return {'auth' : 'success'}


@app.route('/usersession/<some_val>', methods =['GET'])
def getUserSession(some_val):
    if Token.checkToken(session['token'], secret_key)['name'] == session['username']:
        return f"{some_val}"
    return f"No authorization."


@app.route('/clearsession')
def clearsession():
    session.pop('username', default=None)
    session.pop('token', default=None)
    return f"Cleared. Token is now {session.get('token', 'No token')}"


app.run(debug=True)