'''This file contains helper functions'''

# for decorator
from functools import wraps
# for request and response
from flask import request, make_response, jsonify
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


def token_required(f):
    '''Decorator to authenticate token when API call is made'''
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = request.headers.get('apikey', None)
            # token is not passed
            if not token:
                logger.warning('Request without token received')
                return make_response(jsonify({'message' : 'Token not found !!'}), 401)
            # decoding the token to fetch the stored details
            data = Token.checkApiToken(bytes(token, 'latin-1'), SECRET_KEY)
            if "Jessica Temporal" != data.get('username', None):
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


def tryToAddCustomer(form):
    '''Function to add a new customer to database'''
    try:
        username = form.username.data
        logger.info(f'Trying to add a new customer {username}')
        if not checkIfUserIsUnique(username):
            return (False, f'Username {username} is already taken')
        password = form.password.data
        password_hash = PasswordHash.generateHash(password)
        if len(password_hash) == 0:
            return (False, f'Bad password {password}. Use another password.')
        first_name = form.first_name.data
        last_name = form.last_name.data
        address = form.address.data
        mobile_number = form.mobile_number.data
        if len(mobile_number) != 10 or (not mobile_number.isnumeric()) or int(mobile_number) < 0:
            return (False, f'Invalid mobile number {mobile_number}. Enter a valid mobile number')
        params = [username, password_hash, first_name, last_name, address, mobile_number]
        DBConnection.insertRow(CUSTOMER_TABLE, params)
        return (True, f'Customer {username} add')
    except Exception as e:
        logger.exception(f'Error while trying to add user with fields: {username}, {password}, {first_name}, {last_name}, {address}, {mobile_number}')
        return (False, 'Error while trying to sign up. Please try again')