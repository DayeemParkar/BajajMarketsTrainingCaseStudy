'''This file contains helper functions'''

# for decorator
from functools import wraps
# for request and response
from flask import request, make_response, jsonify, session, render_template
# for flask forms
from forms import CustomerForm, AccountForm, LoginForm, TransactionForm
# for logger
from logger_class import logger
# for Token class
from token_class import Token
# for Password Hash class
from password_hash_class import PasswordHash
# for DB
from db_connector_class import DBConnection
# for secret_key
from config import *
# for timestamp
from datetime import datetime


def token_required(f):
    '''Decorator to authenticate token when API call is made'''
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = request.headers.get('apikey', None)
            # token is not passed
            if not token:
                logger.warning('Request does not contain token')
                return make_response(jsonify({'message' : 'Token not found !!'}), 401)
            # decoding the token to fetch the stored details
            data = Token.checkApiToken(bytes(token, 'utf-8'), SECRET_KEY)
            if not data:
                # invalid token
                logger.warning(f'Invalid token {token}')
                return make_response(jsonify({'message' : 'Token is invalid !!'}), 401)
            # create form for checking authorization
            form = CustomerForm()
            form.username.data = data.get('username', '')
            form.password.data = data.get('password', '')
            res = checkCustomerCredentials(form)
            if not res[0]:
                logger.warning(f'Invalid token {token}')
                return make_response(jsonify({'message' : 'Token is invalid !!'}), 401)
        except Exception as e:
            logger.exception(f'Could not authenticate token {token}')
            return make_response(jsonify({'message' : 'Could not verify token !!'}), 400)
        # proceed with functionality
        return  f(*args, **kwargs)
    return decorated


def checkIfUserIsUnique(username):
    '''Function to check if user is unique by checking if an entry exists in DB'''
    return len(DBConnection.selectRows(table_name=CUSTOMER_TABLE, condition=f"{CUSTOMER_TABLE_COLS[1][0]} = '{username}'")) == 0


def checkIfMobileIsUnique(mobile_number):
    '''Function to check if user is unique by checking if an entry exists in DB'''
    return len(DBConnection.selectRows(table_name=CUSTOMER_TABLE, condition=f"{CUSTOMER_TABLE_COLS[6][0]} = '{mobile_number}'")) == 0


def getCustomer(username):
    '''Function to check if customer is valid by checking entry in DB'''
    rows = DBConnection.selectRows(table_name=CUSTOMER_TABLE, condition=f"{CUSTOMER_TABLE_COLS[1][0]} = '{username}'")
    if len(rows) == 0:
        logger.warning(f"Customer retrieve warning: Username {username} not found")
        return None
    return rows[0]


def verifySession():
    try:
        username = session.get('username', '')
        token = session.get('token', '')
        data = Token.checkApiToken(bytes(token, 'utf-8'), SECRET_KEY)
        if not data:
            # invalid token
            logger.warning(f'Could not decode token {token} for user {username}')
            return (False, 'Session was invalid or has expired. Please login again')
        if data.get('username', '') != username:
            # Token does not belong to this customer
            logger.warning(f'Invalid token {token} for user {username}')
            return (False, 'Session was invalid or has expired. Please login again')
        return (True, 'Session is valid')
    except Exception as e:
        logger.exception(f'Could not verify session for user {username} with token {token}')
        return (False, 'Session was invalid or has expired. Please login again')


def tryToAddCustomer(form):
    '''Function to try to add a new customer to database'''
    try:
        username = form.username.data
        logger.info(f'Trying to add a new customer {username}')
        if not checkIfUserIsUnique(username):
            logger.warning(f'Register customer warning: Username {username} is already taken')
            return (False, f'Username {username} is already taken')
        password = form.password.data
        password_hash = PasswordHash.generateHash(password)
        if len(password_hash) == 0:
            logger.warning(f'Register customer warning: Username {username}. Bad password {password}')
            return (False, f'Bad password {password}. Use another password.')
        first_name = form.first_name.data
        last_name = form.last_name.data
        address = form.address.data
        mobile_number = form.mobile_number.data
        if mobile_number // 10000000000 <= 0 and mobile_number // 10000000000 > 9:
            logger.warning(f'Register customer warning: Username {username}, invalid mobile number {mobile_number}')
            return (False, f'Invalid mobile number {mobile_number}. Enter a valid mobile number')
        if not checkIfMobileIsUnique(mobile_number):
            logger.warning(f'Register customer warning: Username {username}, mobile number {mobile_number} is already taken')
            return (False, f'Mobile number {mobile_number} already registered')
        params = [username, password_hash, first_name, last_name, address, mobile_number]
        DBConnection.insertRow(CUSTOMER_TABLE, params)
        return (True, f'Customer {username} created')
    except Exception as e:
        logger.exception(f'Error while trying to add user with fields: {username}, {password}, {first_name}, {last_name}, {address}, {mobile_number}')
        return (False, 'Error while trying to sign up. Please try again')


def checkCustomerCredentials(form):
    '''Function to try to login a customer'''
    username = form.username.data
    password = form.password.data
    customer = getCustomer(username)
    if not customer:
        logger.warning(f'Customer Login warning: Customer {username} does not exist')
        return (False, f'{username} does not exist')
    hashed_password = customer[2]
    if len(hashed_password) == 0:
        logger.warning(f'Customer Login warning: Unable to hash password {password}')
        return (False, f'Unable to verify password {password}')
    if not PasswordHash.verifyHash(hashed_password, password):
        logger.warning(f'Customer Login warning: Invalid password {password} for customer {username}')
        return (False, f'Invalid password')
    logger.info(f'Customer Login info: Customer {username} verified')
    return (True, 'Credential verification successful', customer)


def generatePayload(customer):
    '''Function to generate payload of a customer that would be used for token generation'''
    payload = {
        "username" : customer[1],
        "password" : customer[2],
        "timestamp" : f"{datetime.now()}"
    }
    return payload


def prepareCustomerForLogin(customer):
    '''Function to setup session variables for customer'''
    payload = generatePayload(customer)
    if not payload:
        return (False, 'Authentication failed. Please try again')
    token = Token.generateToken(payload, SECRET_KEY).decode('utf-8')
    if not token:
        return (False, 'Authentication failed. Please try again')
    session['username'] = customer[1]
    session['token'] = token
    logger.info(f"Customer {session['username']} logged in with token {session['token']}")
    return (True, "Successfully logged in")


def tryToAddAccount(form, username):
    '''Function to add a new account to database'''
    try:
        account_type = form.account_type.data
        password = form.password.data
        password_hash = PasswordHash.generateHash(password)
        if len(password_hash) == 0:
            logger.warning(f"Account add warning: Customer {username}. Bad password {password}")
            return (False, f'Bad password {password}. Use another password.')
        balance = form.balance.data
        params = [password_hash, account_type, balance]
        customer = getCustomer(username)
        if not customer:
            logger.warning(f"Account add warning: Customer {username} does not exist")
            return (False, f'Username {username} not found')
        DBConnection.insertRow(ACCOUNT_TABLE, params)
        account_no = DBConnection.selectRows(table_name=ACCOUNT_TABLE, additions=f"ORDER BY {ACCOUNT_TABLE_COLS[0][0]} DESC LIMIT 1")[0][0]
        DBConnection.insertRow(ACCOUNT_MAPPING_TABLE, params=[f"{account_no}", f"{customer[0]}"])
        return (True, f'New account of type {account_type} with balance {balance} added')
    except Exception as e:
        logger.exception(f"Account add error: Customer {username}. Error while trying to adding account: {account_type}, {password}, {balance}")
        return (False, 'Error while trying to add account. Please try again')


def tryToViewTransactionHistory(account_no, username):
    '''Function to view transaction history of a specific account'''
    try:
        rows = DBConnection.selectRows(table_name=TRANSACTION_TABLE, condition=f"{TRANSACTION_TABLE_COLS[1][0]} = '{account_no}' OR {TRANSACTION_TABLE_COLS[2][0]} = '{account_no}'")
        result = []
        for row in rows:
            currrent_result = [row[0]]
            if int(account_no) == row[1]:
                # current account was debited in this transaction
                if row[2]:
                    currrent_result.append(row[2])
                else:
                    currrent_result.append('Withdrew cash')
                currrent_result.append(row[3])
                currrent_result.append('NULL')
            else:
                # current account was credited in this transaction
                if row[1]:
                    currrent_result.append(row[1])
                else:
                    currrent_result.append('Deposited cash')
                currrent_result.append('NULL')
                currrent_result.append(row[3])
            currrent_result.append(row[4])
            result.append(currrent_result)
        return (True, result)
    except Exception as e:
        logger.exception(f'Error while trying to view transaction history of account {account_no}')
        return (False, 'Error while trying to view transaction history. Please try again')


def tryToViewAccounts(customer_id):
    '''Function to try to retrieve all accounts of customer'''
    try:
        DBConnection.dbConnect()
        cur = DBConnection.cur
        sql = f"SELECT account_no, account_type, account_balance from {ACCOUNT_TABLE} where account_no in (select account_no from {ACCOUNT_MAPPING_TABLE} where customer_id = '{customer_id}')"
        cur.execute(sql)
        return cur.fetchall()
    except Exception as e:
        logger.exception(f'Error while trying to view accounts of customer {customer_id}')
        return None


def getViewAccountTemplate(template, title, navid, msg=None):
    customer = getCustomer(session.get('username', ''))
    if not customer:
        logger.warning(f"View account error: Username {session.get(USERNAME, 'no user')}. Customer not found")
        return render_template(template, title=title, id=navid, msg="Could not retrieve accounts", result=False, accountNotSelected=True)
    res = tryToViewAccounts(customer[0])
    if not res:
        logger.warning(f"View account error: Username {session.get(USERNAME, 'no user')}. No accounts")
        return render_template(template, title=title, id=navid, msg="You have no accounts", result=False, accountNotSelected=True)
    return render_template(template, title=title, id=navid, result=res, accountNotSelected=True, msg=msg)


def checkIfAccountBelongsToCustomer(account_no, username):
    '''Function to check if the account belongs to current customer'''
    try:
        customer = getCustomer(username)
        if not customer:
            return False
        rows = DBConnection.selectRows(table_name=ACCOUNT_MAPPING_TABLE, condition=f"{ACCOUNT_MAPPING_TABLE_COLS[0][0]} = {account_no} and {ACCOUNT_MAPPING_TABLE_COLS[1][0]} = {customer[0]}")
        return len(rows) != 0
    except Exception as e:
        return False


def checkIfAccountExists(account_no, password=None):
    '''Function to check if account is unique by checking in DB and password is valid if provided'''
    rows = DBConnection.selectRows(table_name=ACCOUNT_TABLE, condition=f"{ACCOUNT_TABLE_COLS[0][0]} = '{account_no}'")
    if not password:
        return (len(rows) != 0, rows)
    if len(rows) == 0:
        return (False, rows)
    password_hash = rows[0][1]
    return (PasswordHash.verifyHash(password_hash, password), rows)


def tryToMakeDeposit(account_no, amount, password, username):
    try:
        res = checkIfAccountExists(account_no, password)
        if not res[0]:
            return (False, "Invalid credentials for account")
        if not checkIfAccountBelongsToCustomer(account_no, username):
            return (False, "Account does not belong to you")
        account_row = res[1][0]
        balance = int(account_row[3])
        new_amount = balance + amount
        DBConnection.updateRow(ACCOUNT_TABLE, f"{ACCOUNT_TABLE_COLS[3][0]} = '{new_amount}'", f"{ACCOUNT_TABLE_COLS[0][0]} = {account_no}")
        DBConnection.insertRow(TRANSACTION_TABLE, params=['NULL', account_no, f"{amount}", f"'{DBConnection.getTimeStamp()}'"])
        return (True, 'Deposit successful')
    except Exception as e:
        logger.exception(f"Deposit error: Failed to deposit {amount} into {account_no}")
        return (False, 'Error while depositing. Please try again')
  

def tryToMakeWithdrawal(account_no, amount, password, username):
    '''Function to try and withdraw cash from account'''
    try:
        res = checkIfAccountExists(account_no, password)
        if not res[0]:
            return (False, "Invalid credentials for account")
        if not checkIfAccountBelongsToCustomer(account_no, username):
            return (False, "Account does not belong to you")
        account_row = res[1][0]
        balance = int(account_row[3])
        if balance < amount:
            return(False, "Not Enough Balance")
        new_amount = balance - amount
        DBConnection.updateRow(ACCOUNT_TABLE, f"{ACCOUNT_TABLE_COLS[3][0]} = '{new_amount}'", f"{ACCOUNT_TABLE_COLS[0][0]} = {account_no}")
        DBConnection.insertRow(TRANSACTION_TABLE, params=[account_no, 'NULL', f"{amount}", f"'{DBConnection.getTimeStamp()}'"])
        return (True, 'Withdrawal successful')
    except Exception as e:
        logger.exception(f"Withdrawal error: Failed to withdraw {amount} from {account_no}")
        return (False, 'Error while withdrawing. Please try again')


def tryToMakeTransaction(from_account_no, to_account_no, amount, password, username):
    '''Function to try to transfer from one account to another'''
    try:
        res1 = checkIfAccountExists(from_account_no, password)
        res2 = checkIfAccountExists(to_account_no)
        if not (res1[0] and res2[0]):
            return (False, "One or more accounts do not exist or invalid credentials. Please try again")
        if not checkIfAccountBelongsToCustomer(from_account_no, username):
            return (False, "Account does not belong to you")
        from_account_row = res1[1][0]
        to_account_row = res2[1][0]
        from_balance = int(from_account_row[3])
        to_balance = int(to_account_row[3])
        if from_balance < amount:
            return(False, "Not Enough Balance")
        new_from_amount = from_balance - amount
        new_to_amount = to_balance + amount
        DBConnection.updateRow(ACCOUNT_TABLE, f"{ACCOUNT_TABLE_COLS[3][0]} = '{new_from_amount}'", f"{ACCOUNT_TABLE_COLS[0][0]} = {from_account_no}")
        DBConnection.updateRow(ACCOUNT_TABLE, f"{ACCOUNT_TABLE_COLS[3][0]} = '{new_to_amount}'", f"{ACCOUNT_TABLE_COLS[0][0]} = {to_account_no}")
        DBConnection.insertRow(TRANSACTION_TABLE, params=[from_account_no, to_account_no, f"{amount}", f"'{DBConnection.getTimeStamp()}'"])
        return (True, 'Transaction successful')
    except Exception as e:
        logger.exception(f"Deposit error: Failed to transfer {amount} from account {from_account_no} into account {to_account_no}")
        return (False, 'Error Making Transaction. Please try again')