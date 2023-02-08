'''This file contains the app'''

# for running app
from flask import Flask, redirect, url_for
# for swagger ui
from flask_swagger_ui import get_swaggerui_blueprint
# for helper functions, flask forms, logger, Token class, PasswordHash class, DB, config vars
from helpers import *


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


# application routes
@app.route('/', methods=['GET','POST'])
def home():
    '''Home page'''
    try:
        if not session.get('username', None):
            return redirect(url_for('login'))
        return render_template('home.html',  title='Home', id=['nav1'], username=session['username'], token=session['token'])
    except Exception as e:
        logger.exception(f"Error while accessing home. User: {session.get(USERNAME, 'no user')}")
        return f"{'message': 'server error'}"


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
            form.mobile_number.data = ''
            if not res[0]:
                # unable to register customer
                return render_template('signup_form.html', title='Signup', form=form, msg=res[1])
            # customer registered, proceed to login
            logger.info(res[1])
            return render_template('login_form.html', title='Login', form=form, msg=res[1])
        return render_template('signup_form.html', title='Signup', form=form)
    except Exception as e:
        logger.exception('Error while accessing signup')
        return render_template('signup_form.html', title='Signup', form=form)


@app.route('/login', methods=['GET','POST'])
def login():
    '''Login Page'''
    try:
        form = LoginForm()
        if form.validate_on_submit():
            res = checkCustomerCredentials(form)
            form.username.data = ''
            form.password.data = ''
            if not res[0]:
                # Could not log in due to invalid credentials
                return render_template('login_form.html', title='Login', form=form, msg=res[1])
            # Valid credentials
            customer = res[2]
            res = prepareCustomerForLogin(customer)
            if not res[0]:
                # Could not authenticate
                return render_template('login_form.html', title='Login', form=form, msg=res[1])
            # Login successful
            return redirect(url_for('home'))
        return render_template('login_form.html', title='Login', form=form)
    except Exception as e:
        logger.exception(f"Error while accessing login. User: {session.get(USERNAME, 'no user')}")
        return render_template('login_form.html', title='Login', form=form)


@app.route('/addaccount', methods=['GET','POST'])
def addAccount():
    try:
        if not verifySession():
            return redirect(url_for('clearsession'))
        form = AccountForm()
        if form.validate_on_submit():
            res = tryToAddAccount(form)
            form.account_type.data = ''
            form.balance.data = ''
            form.balance.data = ''
            if not res[0]:
                # unable to add account
                return render_template('new_account.html', title='Add account', form=form, id=["nav3", "nav4"], msg=res[1])
            logger.info(f"Created new account for customer {session.get(USERNAME, 'no user')}")
            return redirect(url_for('viewaccount'))
        return render_template('new_account.html', title='Add account', form=form, id=["nav3", "nav4"])
    except Exception as e:
        logger.exception(f"Error while accessing add account page. User: {session.get(USERNAME, 'no user')}")
        return render_template('new_account.html', title='Add account', form=form, id=["nav3", "nav4"])


@app.route('/viewaccount', methods=['GET','POST'])
def viewAccount():
    try:
        if not verifySession():
            return redirect(url_for('clearsession'))
        return getViewAccountTemplate(template='view_account.html', title='View accounts', navid=['nav3', 'nav5'], msg=None)
        # customer = getCustomer(session.get(USERNAME, ''))
        # if not customer:
        #     logger.warning(f"View account error: Username {session.get(USERNAME, 'no user')}. Customer not found")
        #     return render_template('view_account.html', title='View accounts', id=["nav3", "nav5"], msg="Could not retrieve accounts")
        # res = tryToViewAccounts(customer[0])
        # if not res:
        #     logger.warning(f"View account error: Username {session.get(USERNAME, 'no user')}. No accounts")
        #     return render_template('view_account.html', title='View accounts', id=["nav3", "nav5"], msg="You have no accounts")
        # return render_template('view_account.html', title='View accounts', id=["nav3", "nav5"], result=res)
    except Exception as e:
        logger.exception(f"Error while accessing add account page. User: {session.get(USERNAME, 'no user')}")
        return render_template('view_account.html', title='Add account', id=["nav3", "nav4"])


@app.route('/history/<account_no>')
def viewTransactionHistory(account_no):
    '''Page to view transaction history of an account'''
    try:
        if not verifySession():
            return redirect(url_for('clearsession'))
        result = tryToViewTransactionHistory(account_no)
        if not result[0]:
            # could not retrieve rows
            return render_template('transaction_history.html', title=f"Account {account_no} history", id=["nav7"])
        # render transaction history table
        logger.info(f'Displaying transaction history of account {account_no}')
        return render_template('transaction_history.html', title=f"Account {account_no} history", id=["nav7"], result=result[1])
    except Exception as e:
        logger.exception(f'Error while accessing login. User: {session.get(USERNAME, "no user")}')
        return render_template('transaction_history.html', title=f"Account {account_no} history", id=["nav7"])


@app.route('/deposit/<account_no>', methods=['GET','POST'])
def deposit(account_no):
    try:
        if not verifySession():
            return redirect(url_for('clearsession'))
        form = TransactionForm()
        if form.validate_on_submit():
            amount = form.amount.data
            password = form.password.data
            form.amount.data = ''
            form.password.data = ''
            # accountNotSelected, result
            res = tryToMakeDeposit(account_no, amount, password, session.get(USERNAME, ''))
            if not res[0]:
                # Failed to make deposit
                return getViewAccountTemplate(template='deposit.html', title='Deposit', navid=["nav9"], msg=res[1])
            # deposit successful
            return redirect(url_for('viewTransactionHistory', account_no=account_no))
        return render_template('deposit.html', title="Deposit", id=["nav9"], accountNotSelected=not checkIfAccountExists(account_no))
    except Exception as e:
        return render_template('deposit.html', title="Deposit", id=["nav9"], accountNotSelected=True)


@app.route('/withdraw/<account_no>', methods=['GET','POST'])
def withdrawal(account_no):
    try:
        if not verifySession():
            return redirect(url_for('clearsession'))
        return render_template('withdrawal.html', title="Withdraw", id=["nav10"], accountNotSelected=not checkIfAccountExists(account_no))
    except Exception as e:
        return render_template('withdrawal.html', title="Withdraw", id=["nav10"], accountNotSelected=True)


@app.route('/transaction/<account_no>', methods=['GET','POST'])
def transaction(account_no):
    try:
        if not verifySession():
            return redirect(url_for('clearsession'))
        return render_template('transaction.html', title="Make Transaction", id=["nav6", "nav7"], accountNotSelected=not checkIfAccountExists(account_no))
    except Exception as e:
        return render_template('transaction.html', title="Make Transaction", id=["nav6", "nav7"], accountNotSelected=True)


@app.route('/clearsession')
def clearsession():
    '''Page to clear session variables'''
    try:
        logger.info(f"Clearing session variables for user {session[USERNAME]}")
        session.pop(USERNAME, default=None)
        session.pop(TOKEN, default=None)
        logger.info(f'Session variables cleared')
        return redirect(url_for('login'))
    except Exception as e:
        logger.exception(f'Error while clearing session')
        return redirect(url_for('login'))


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
        # form to check authorization
        form = CustomerForm()
        form.username.data = username
        form.password.data = password
        res = checkCustomerCredentials(form)
        if not res[0]:
            logger.warning(f'Invalid credentials: Username {username}, Password {password}')
            return make_response(jsonify({'token' : '', 
                                          'success' : False}), 400)
        payload['timestamp'] = f"{datetime.now()}"
        token = Token.generateToken(payload, SECRET_KEY).decode('utf-8')
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