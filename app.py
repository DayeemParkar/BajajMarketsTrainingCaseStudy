'''This file contains the app'''

# for running app
from flask import Flask, session, render_template, redirect, url_for
# for swagger ui
from flask_swagger_ui import get_swaggerui_blueprint
# for helper functions, logger, Token class, PasswordHash class, DB, config vars
from helpers import *
# for flask forms
from forms import CustomerForm, AccountForm, LoginForm


app = Flask(__name__)
# app config
app.config['SECRET_KEY'] = SECRET_KEY

# swagger config
SWAGGER_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config=SWAGGER_BLUEPRINT_CONFIG
)
app.register_blueprint(SWAGGER_BLUEPRINT, url_prefix=SWAGGER_URL)

# testing variables
payload_data = {
    "username": "Jessica Temporal",
    "password": "JessPass"
}


# application routes
@app.route('/')
def home():
    '''Home page'''
    try:
        # rows = DBConnection.selectRows(CUSTOMER_TABLE)
        # session[USERNAME] = payload_data['username']
        # session[TOKEN] = Token.generateToken(payload_data, SECRET_KEY).decode('latin-1')
        # logger.info(f'Generated token {session[TOKEN]} for customer {session[USERNAME]}')
        # return f"{session[TOKEN]} {rows}"
        return redirect(url_for('login'))
    except Exception as e:
        logger.exception(f'Error while accessing home for {session.get(USERNAME, "no user")}')
        return f"{e}"


@app.route('/signup', methods=['GET','POST'])
def signup():
    '''Signup Page'''
    try:
        form = CustomerForm()
        if form.validate_on_submit():
            res = tryToAddCustomer(form)
            form.username.data = ''
            form.password.data = ''
            form.first_name.data = ''
            form.last_name.data = ''
            form.address.data = ''
            form.mobile_number.data = -1
            # unable to register customer
            if not res[0]:
                logger.warning(res[1])
                return render_template('signup_form.html', title='Signup', form=form, id='nav3', msg=res[1])
            # customer registered, proceed to login
            logger.info(res[1])
            return render_template('login_form.html', title='Login', form=form, id='nav3', msg=res[1])
        return render_template('signup_form.html', title='Signup', form=form, id='nav3')
    except Exception as e:
        logger.exception('Error while accessing signup')
        return f"{e}"


@app.route('/login')
def login():
    '''Login Page'''
    try:
        form = LoginForm()
        return render_template('login_form.html', title='Login', form=form, id='nav3')
    except Exception as e:
        logger.exception(f'Error while accessing login. User: {session.get(USERNAME, "no user")}')
        return f"{e}"


@app.route('/usersession/<some_val>', methods =['GET'])
def getUserSession(some_val):
    '''Test page to verify session token'''
    if Token.checkApiToken(session.get(TOKEN, ''), SECRET_KEY).get('username', '') == session.get(USERNAME, None):
        logger.info(f'Customer {session.get(USERNAME, "no user")} has valid token {session.get(TOKEN, "no token")}')
        return f"{some_val}"
    logger.warning(f'Customer {session.get(USERNAME, "no user")} has invalid token {session.get(TOKEN, "no token")}')
    return f"No authorization."


@app.route('/clearsession')
def clearsession():
    '''Page to clear session variables'''
    try:
        logger.info(f'Clearing session variables for user {session[USERNAME]}')
        session.pop(USERNAME, default=None)
        session.pop(TOKEN, default=None)
        logger.info(f'Session variables cleared')
        return f"Cleared. Token is now {session.get(TOKEN, 'No token')}"
    except Exception as e:
        logger.exception(f'Error while clearing session')
        return f"{e}"


# API methods
@app.route('/api/retrievetoken', methods=['POST'])
def retrieveToken():
    '''Retrieve Token'''
    try:
        payload = request.get_json()
        username = payload.get('username', '')
        password = payload.get('password', '')
        if len(username) == 0 or len(password) == 0 or len(payload) > 2:
            logger.warning(f'Bad request while retrieving api token. username length: {len(username)}. password length: {len(password)}. payload length: {len(payload)}')
            return make_response(jsonify({'token' : '', 
                                          'success' : False}), 400)
        token = Token.generateToken(payload, SECRET_KEY).decode('latin-1')
        if not token:
            logger.warning(f'Unable to generate token for {payload}')
            return make_response(jsonify({'token' : token, 
                                          'success' : False}), 500)
        logger.info(f'Generated token {token} for {payload}')
        return make_response(jsonify({'token' : token, 
                                      'success' : True}), 200)
    except Exception as e:
        logger.exception(f'Error while generating token for {payload}')
        return make_response(jsonify({'token' : '', 
                                      'success' : False}), 500)


@app.route('/api/verifytoken', methods =['GET'])
@token_required
def verifyToken():
    '''Verify Token'''
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