'''This file contains helper functions'''

# for decorator
from functools import wraps
# for request and response
from flask import request, make_response, jsonify
# for logger
from logger_class import logger
# for Token class
from token_class import Token
# for secret_key
from config import SECRET_KEY


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