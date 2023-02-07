'''This file contains helper functions'''

# for decorator
from functools import wraps
# for request and response
from flask import request, make_response, jsonify, session
# for flask forms
from forms import CustomerForm, AccountForm, LoginForm
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
        return None
    return rows[0]


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


def tryToAddAccount(form):
    '''Function to add a new account to database'''
    try:
        account_type = form.account_type.data
        password = form.password.data
        password_hash = PasswordHash.generateHash(password)
        if len(password_hash) == 0:
            return (False, f'Bad password {password}. Use another password.')
        balance = form.balance.data
        params = [password, account_type, balance]
        DBConnection.insertRow(ACCOUNT_TABLE, params)
        return (True, f'New account of type {account_type} with balance {balance} added')
    except Exception as e:
        logger.exception(f'Error while trying to adding account: {account_type}, {password}, {balance}')
        return (False, 'Error while trying to sign up. Please try again')


def tryToViewTransactionHistory(account_no):
    '''Function to view transaction history of a specific account'''
    try:
        rows = DBConnection.selectRows(table_name=TRANSACTION_TABLE, condition=f"{TRANSACTION_TABLE_COLS[1][0]} = '{account_no}'")
        result = []
        for row in rows:
            currrent_result = [row[0]]
            if account_no == row[1]:
                # current account was debited in this transaction
                currrent_result.append(row[1])
                currrent_result.append('NULL')
                currrent_result.append(row[3])
            else:
                # current account was credited in this transaction
                currrent_result.append(row[2])
                currrent_result.append(row[3])
                currrent_result.append('NULL')
            currrent_result.append(row[4])
            result.append(currrent_result)
        return (True, result)
    except Exception as e:
        logger.exception(f'Error while trying to view transaction history of account {account_no}')
        return (False, 'Error while trying to view transaction history. Please try again')


def tryToViewAccounts(customer_id):
    try:
        DBConnection.dbConnect()
        cur = DBConnection.cur
        sql = f"SELECT account_no, account_type, account_balance from {ACCOUNT_TABLE} where account_no in (select account_no from {ACCOUNT_MAPPING_TABLE} where customer_id = '{customer_id}')"
        cur.execute(sql)
        return cur.fetchall()
    except Exception as e:
        logger.exception(f'Error while trying to view accounts of customer {customer_id}')
        return ()