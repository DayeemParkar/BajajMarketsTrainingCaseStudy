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
        customer = getCustomer(session.get(USERNAME, ''))
        return render_template('home.html',  title='Home', id=['nav1'], customer=customer, token=session['token'])
    except Exception as e:
        logger.exception(f"Error while accessing home. User: {session.get(USERNAME, 'no user')}")
        return redirect(url_for('clearsession'))


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
        if not verifySession()[0]:
            return redirect(url_for('clearsession'))
        form = AccountForm()
        if form.validate_on_submit():
            res = tryToAddAccount(form, session.get(USERNAME, ''))
            form.account_type.data = ''
            form.password.data = ''
            form.balance.data = ''
            if not res[0]:
                # unable to add account
                return render_template('new_account.html', title='Add account', form=form, id=["nav3", "nav4"], msg=res[1])
            logger.info(f"Created new account for customer {session.get(USERNAME, 'no user')}")
            return redirect(url_for('viewAccount'))
        return render_template('new_account.html', title='Add account', form=form, id=["nav3", "nav4"])
    except Exception as e:
        logger.exception(f"Error while accessing add account page. User: {session.get(USERNAME, 'no user')}")
        return render_template('new_account.html', title='Add account', form=form, id=["nav3", "nav4"])


@app.route('/viewaccount', methods=['GET','POST'])
def viewAccount():
    try:
        if not verifySession()[0]:
            return redirect(url_for('clearsession'))
        # return getViewAccountTemplate(template='view_account.html', title='View accounts', navid=['nav3', 'nav5'], msg=None)
        customer = getCustomer(session.get(USERNAME, ''))
        if not customer:
            logger.warning(f"View account error: Username {session.get(USERNAME, 'no user')}. Customer not found")
            return render_template('view_account.html', title='View accounts', id=["nav3", "nav5"], msg="Could not retrieve accounts")
        res = tryToViewAccounts(customer[0])
        if not res:
            logger.warning(f"View account error: Username {session.get(USERNAME, 'no user')}. No accounts")
            return render_template('view_account.html', title='View accounts', id=["nav3", "nav5"], msg="You have no accounts")
        return render_template('view_account.html', title='View accounts', id=["nav3", "nav5"], result=res)
    except Exception as e:
        logger.exception(f"Error while accessing add account page. User: {session.get(USERNAME, 'no user')}")
        return render_template('view_account.html', title='Add account', id=["nav3", "nav4"])


@app.route('/history/<account_no>')
def viewTransactionHistory(account_no):
    '''Page to view transaction history of an account'''
    try:
        if not verifySession()[0]:
            return redirect(url_for('clearsession'))
        result = tryToViewTransactionHistory(account_no, session.get(USERNAME, ''))
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
        if not verifySession()[0]:
            return redirect(url_for('clearsession'))
        form = TransactionForm()
        form.transaction_account_no.data = '-1'
        if form.validate_on_submit():
            amount = form.amount.data
            password = form.password.data
            form.amount.data = ''
            res = tryToMakeDeposit(account_no, amount, password, session.get(USERNAME, ''))
            if not res[0]:
                # Failed to deposit
                return render_template('deposit.html', title='Deposit', navid=["nav6", "nav9"], form=form, accountNotSelected=False, msg=res[1])
            # deposit successful
            return redirect(url_for('viewTransactionHistory', account_no=account_no))
        if checkIfAccountExists(account_no)[0]:
            return render_template('deposit.html', title='Deposit', navid=["nav6", "nav9"], form=form)
        return getViewAccountTemplate(template='deposit.html', title='Deposit', navid=["nav6", "nav9"], msg=None)
    except Exception as e:
        return render_template('deposit.html', title="Deposit", id=["nav6", "nav9"], accountNotSelected=True)


@app.route('/withdraw/<account_no>', methods=['GET','POST'])
def withdrawal(account_no):
    try:
        if not verifySession()[0]:
            return redirect(url_for('clearsession'))
        form = TransactionForm()
        form.transaction_account_no.data = '-1'
        if form.validate_on_submit():
            amount = form.amount.data
            password = form.password.data
            form.amount.data = ''
            res = tryToMakeWithdrawal(account_no, amount, password, session.get(USERNAME, ''))
            if not res[0]:
                # Failed to withdraw
                return render_template('withdrawal.html', title='Withdraw', navid=["nav6", "nav10"], form=form, accountNotSelected=False, msg=res[1])
            # withdrawal successful
            return redirect(url_for('viewTransactionHistory', account_no=account_no))
        if checkIfAccountExists(account_no)[0]:
            return render_template('withdrawal.html', title='Withdraw', navid=["nav6", "nav10"], form=form)
        return getViewAccountTemplate(template='withdrawal.html', title='Withdraw', navid=["nav6", "nav10"], msg=None)
    except Exception as e:
        return render_template('withdrawal.html', title="Withdraw", id=["nav6", "nav10"], accountNotSelected=True)


@app.route('/transaction/<account_no>', methods=['GET','POST'])
def transaction(account_no):
    try:
        if not verifySession()[0]:
            return redirect(url_for('clearsession'))
        form = TransactionForm()
        if form.validate_on_submit():
            amount = form.amount.data
            password = form.password.data
            transaction_account_no = form.transaction_account_no.data
            form.amount.data = ''
            form.transaction_account_no.data = ''
            res = tryToMakeTransaction(account_no, transaction_account_no, amount, password, session.get(USERNAME, ''))
            if not res[0]:
                # Failed to make transaction
                return render_template('transaction.html', title="Transaction", id=["nav6", "nav7"], form=form, accountNotSelected=False, msg=res[1])
            # transaction successful
            return redirect(url_for('viewTransactionHistory', account_no=account_no))
        if checkIfAccountExists(account_no)[0]:
            return render_template('transaction.html', title='Transaction', navid=["nav6", "nav7"], form=form)
        return getViewAccountTemplate(template='transaction.html', title='Transaction', navid=["nav6", "nav7"], msg=None)
    except Exception as e:
        return render_template('transaction.html', title="Transaction", id=["nav6", "nav7"], accountNotSelected=True)


@app.route('/clearsession')
def clearsession():
    '''Page to clear session variables'''
    try:
        logger.info(f"Clearing session variables for user {session.get(USERNAME, 'no user')}")
        session.pop(USERNAME, default=None)
        session.pop(TOKEN, default=None)
        session.pop(ADMIN_USERNAME, default=None)
        logger.info(f'Session variables cleared')
        return redirect(url_for('login'))
    except Exception as e:
        logger.exception(f'Error while clearing session')
        return redirect(url_for('login'))


@app.route('/deletecustomer/<customer_id>')
def deleteCustomer(customer_id):
    try:
        if session.get('admin', '') != ADMIN_USERNAME:
            return redirect(url_for('home'))
        res = tryToDeleteCustomer(customer_id)
        logger.info(res[1])
        return redirect(url_for('adminViewCustomers'))
    except:
        logger.exception(f'Error while deleting customer with id {customer_id}')
        return redirect(url_for('adminViewCustomers'))


@app.route('/modifycustomer/<customer_id>', methods=['GET','POST'])
def modifyCustomer(customer_id):
    try:
        if session.get('admin', '') != ADMIN_USERNAME:
            return redirect(url_for('home'))
        form = CustomerModifyForm()
        if form.validate_on_submit():
            res = tryToModifyCustomer(customer_id, form.password.data, form.address.data, form.mobile_number.data)
            if not res[0]:
                logger.warning(res[1])
                return render_template('modify_customer.html', title=f'Modify customer {customer_id}', form=form, msg=res[1])
            logger.info(res[1])
            return redirect(url_for('adminViewCustomers'))
        return render_template('modify_customer.html', title=f'Modify customer {customer_id}', form=form)
    except:
        logger.exception(f'Error while accesing form to modify customer')
        return render_template('modify_customer.html', title=f'Modify customer {customer_id}', form=form)


@app.route('/deleteaccount/<account_no>')
def deleteAccount(account_no):
    try:
        if session.get('admin', '') != ADMIN_USERNAME:
            return redirect(url_for('home'))
        res = tryToDeleteAccount(account_no)
        logger.info(res[1])
        return redirect(url_for('adminViewAccounts'))
    except:
        logger.exception(f'Error while deleting account with id {account_no}')
        return redirect(url_for('adminViewAccounts'))


@app.route('/modifyaccount/<account_no>', methods=['GET','POST'])
def modifyAccount(account_no):
    try:
        if session.get('admin', '') != ADMIN_USERNAME:
            return redirect(url_for('home'))
        form = AccountModifyForm()
        if form.validate_on_submit():
            res = tryToModifyAccount(account_no, form.password.data, form.account_type.data)
            if not res[0]:
                logger.warning(res[1])
                return render_template('modify_account.html', title=f'Modify account {account_no}', form=form, msg=res[1])
            logger.info(res[1])
            return redirect(url_for('adminViewAccounts'))
        return render_template('modify_account.html', title=f'Modify account {account_no}', form=form)
    except:
        logger.exception(f'Error while accesing form to modify customer')
        return render_template('modify_account.html', title=f'Modify account {account_no}', form=form)


# Admin routes
@app.route('/admin')
def admin():
    '''Clear session variables and redirect to admin login'''
    try:
        logger.info(f"Clearing session variables")
        session.pop(USERNAME, default=None)
        session.pop(TOKEN, default=None)
        session.pop(ADMIN_USERNAME, default=None)
        logger.info(f'Session variables cleared')
        return redirect(url_for('adminlogin'))
    except Exception as e:
        logger.exception(f'Session variables were already cleared')
        return redirect(url_for('adminlogin'))


@app.route('/admin/login', methods=['GET','POST'])
def adminlogin():
    '''Page to login admin'''
    try:
        if verifySession()[0]:
            return redirect(url_for('home'))
        form = LoginForm()
        if form.validate_on_submit():
            res = form.username.data == ADMIN_USERNAME and PasswordHash.verifyHash(ADMIN_PASSWORD, form.password.data)
            form.username.data = ''
            form.password.data = ''
            if not res:
                # Could not log in due to invalid credentials
                return render_template('admin_login.html', title='Admin Login', form=form, msg='Invalid credentials')
            # Login successful
            session['admin'] = ADMIN_USERNAME
            return redirect(url_for('adminViewCustomers'))
        return render_template('admin_login.html', title='Admin Login', form=form)
    except Exception as e:
        logger.exception(f"Error while accessing admin login")
        return render_template('admin_login.html', title='Admin Login', form=form)


@app.route('/admin/customers')
def adminViewCustomers():
    try:
        if session.get('admin', '') != ADMIN_USERNAME:
            return redirect(url_for('home'))
        rows = displayCustomers()
        if len(rows) == 0:
            return render_template('admin_view_customer.html', title='Customers', id=["nav1"])
        return render_template('admin_view_customer.html', title='Customers', id=["nav1"], result=rows)
    except Exception as e:
        logger.exception(f"Error while accessing admin customer display page")
        return render_template('admin_view_customer.html', title='Customers', id=["nav1"])


@app.route('/admin/accounts')
def adminViewAccounts():
    try:
        if session.get('admin', '') != ADMIN_USERNAME:
            return redirect(url_for('home'))
        rows = displayAccount()
        if len(rows) == 0:
            return render_template('admin_view_account.html', title='Accounts', id=["nav2"])
        return render_template('admin_view_account.html', title='Accounts', id=["nav2"], result=rows)
    except Exception as e:
        logger.exception(f"Error while accessing admin account display page")
        return render_template('admin_view_account.html', title='Accounts', id=["nav2"])


@app.route('/admin/history')
def adminViewHistory():
    try:
        if session.get('admin', '') != ADMIN_USERNAME:
            return redirect(url_for('home'))
        res = displayTransactions()
        if not res[0]:
            return render_template('admin_view_history.html', title='Transaction History', id=["nav3"])
        rows = res[1]
        if len(rows) == 0:
            return render_template('admin_view_history.html', title='Transaction History', id=["nav3"])
        return render_template('admin_view_history.html', title='Transaction History', id=["nav3"], result=rows)
    except Exception as e:
        logger.exception(f"Error while accessing admin account display page")
        return render_template('admin_view_history.html', title='Transaction History', id=["nav3"])


@app.route('/admin/logout')
def adminLogout():
    try:
        session.pop('home', default=None)
        return redirect(url_for('home'))
    except Exception as e:
        logger.exception(f"Error while logging out admin account")
        return redirect(url_for('home'))


# API methods
@app.route('/api')
def api():
    '''Clear session variables and redirect to swagger ui page'''
    try:
        logger.info(f"Clearing session variables")
        session.pop(USERNAME, default=None)
        session.pop(TOKEN, default=None)
        session.pop(ADMIN_USERNAME, default=None)
        logger.info(f'Session variables cleared')
        return redirect('/swagger')
    except Exception as e:
        logger.exception(f'Session variables were already cleared')
        return redirect('/swagger')


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


@app.route('/api/addaccount', methods =['POST'])
@token_required
def apiAddAccount():
    '''Add Account'''
    try:
        payload = request.get_json()
        customer = Token.checkApiToken(request.headers.get('apikey', ''), SECRET_KEY)
        form = AccountForm()
        form.account_type.data = payload.get('account_type', '')
        form.password.data = payload.get('password', '')
        form.balance.data = payload.get('balance', '')
        res = tryToAddAccount(form, customer.get('username', ''))
        form.account_type.data = ''
        form.password.data = ''
        form.balance.data = ''
        if not res[0]:
            # unable to add account
            return make_response(jsonify({'message' : 'Unable to add account', 'account' : ''}), 400)
        logger.info(f"Created new account for api customer")
        return make_response(jsonify({'message' : 'Account added', 'account' : f"{res[1]}"}), 200)
    except Exception as e:
        logger.exception(f"Api error while accessing add account page")
        return make_response(jsonify({'message' : 'Failed due to input error', 'account' : ''}), 500)


@app.route('/api/viewaccount', methods =['GET'])
@token_required
def apiViewAccount():
    '''View Accounts'''
    try:
        customer = Token.checkApiToken(request.headers.get('apikey', ''), SECRET_KEY)
        customer_id = getCustomer(customer.get('username', ''))[0]
        accounts = tryToViewAccounts(customer_id)
        logger.info(f"Showing accounts for api customer")
        return make_response(jsonify({'message' : 'Successfully fetched accounts', 'accounts' : f"{accounts}"}), 200)
    except Exception as e:
        logger.exception(f"Api error while viewing accounts")
        return make_response(jsonify({'message' : 'Failed due to server error', 'accounts' : f'{[]}'}), 500)


@app.route('/api/viewtransactionhistory', methods =['GET'])
@token_required
def apiTransactionHistory():
    '''View History'''
    try:
        customer = Token.checkApiToken(request.headers.get('apikey', ''), SECRET_KEY)
        account_no = request.headers.get('account_no', '')
        history = tryToViewTransactionHistory(account_no, customer.get('username', ''))
        if not history[0]:
            return make_response(jsonify({'message' : f"{history[1]}", 'history' : f'{[]}'}), 400)
        logger.info(f"Showing history to api customer")
        return make_response(jsonify({'message' : 'History fetched', 'history' : f"{history[1]}"}), 200)
    except Exception as e:
        logger.exception(f"Api error while retrieving transaction history")
        return make_response(jsonify({'message' : 'Failed due to server error', 'history' : f'{[]}'}), 500)


@app.route('/api/maketransaction', methods =['POST'])
@token_required
def apiTransaction():
    '''Perform Transaction'''
    try:
        customer = Token.checkApiToken(request.headers.get('apikey', ''), SECRET_KEY)
        payload = request.get_json()
        from_account = payload.get('from_account', -1)
        to_account = payload.get('to_account', -1)
        amount = payload.get('amount', 0)
        password = payload.get('account_password', '')
        res = tryToMakeTransaction(from_account, to_account, amount, password, customer.get('username', ''))
        if not res[0]:
            return make_response(jsonify({'message' : f'{res[1]}'}), 400)
        return make_response(jsonify({'message' : f'{res[1]}'}), 200)
    except Exception as e:
        logger.exception(f"Api error while making transaction")
        return make_response(jsonify({'message' : 'Failed due to server error'}), 500)


@app.route('/api/deposit', methods =['POST'])
@token_required
def apiDeposit():
    '''Deposit Cash'''
    try:
        customer = Token.checkApiToken(request.headers.get('apikey', ''), SECRET_KEY)
        payload = request.get_json()
        account = payload.get('account_no', -1)
        amount = payload.get('amount', 0)
        password = payload.get('account_password', '')
        res = tryToMakeDeposit(f"{account}", amount, password, customer.get('username', ''))
        if not res[0]:
            return make_response(jsonify({'message' : f'{res[1]}'}), 400)
        return make_response(jsonify({'message' : f'{res[1]}'}), 200)
    except Exception as e:
        logger.exception(f"Api error while depositing")
        return make_response(jsonify({'message' : 'Failed due to server error'}), 500)


@app.route('/api/withdraw', methods =['POST'])
@token_required
def apiWithdraw():
    '''Withdraw Cash'''
    try:
        customer = Token.checkApiToken(request.headers.get('apikey', ''), SECRET_KEY)
        payload = request.get_json()
        account = payload.get('account_no', -1)
        amount = payload.get('amount', 0)
        password = payload.get('account_password', '')
        res = tryToMakeWithdrawal(f"{account}", amount, password, customer.get('username', ''))
        if not res[0]:
            return make_response(jsonify({'message' : f'{res[1]}'}), 400)
        return make_response(jsonify({'message' : f'{res[1]}'}), 200)
    except Exception as e:
        logger.exception(f"Api error while depositing")
        return make_response(jsonify({'message' : 'Failed due to server error'}), 500)


# error handling
@app.errorhandler(400)
def handle_400_error(_error):
    """Return a http 400 error to client"""
    return redirect(url_for('home'))


@app.errorhandler(401)
def handle_401_error(_error):
    """Return a http 401 error to client"""
    return redirect(url_for('home'))


@app.errorhandler(404)
def handle_404_error(_error):
    """Return a http 404 error to client"""
    return redirect(url_for('home'))


@app.errorhandler(500)
def handle_500_error(_error):
    """Return a http 500 error to client"""
    return redirect(url_for('home'))


app.run(debug=True)