'''This file contains the token class'''

# for tokens
import jwt
from jwt.exceptions import ExpiredSignature, InvalidAlgorithmError, InvalidKeyError, InvalidTokenError
# for logger
from logger_class import logger


class Token:
    '''Class containing methods for authentication functionality'''
    _instance = None
    
    def __new__(cls):
        '''Override new to make it a singleton'''
        if not cls._instance:
            cls._instance = super(Token, cls).__new__(cls)
        return cls._instance
    
    
    @classmethod
    def generateToken(cls, payload, key):
        '''Generates a token'''
        try:
            return jwt.encode(payload=payload, key=key,)
        except InvalidKeyError as ike:
            logger.exception(f'Key error while generating token for {payload}: {ike}')
            return None
    
    
    @classmethod
    def checkApiToken(cls, token, key):
        '''Authenticates the token'''
        header = jwt.get_unverified_header(token)
        try:
            payload = jwt.decode(token, key=key, algorithms=[header['alg']],)
            logger.info(f'Decoded token {token} to get {payload}')
            return payload
        except ExpiredSignature as es:
            logger.exception(f'Signature for token {token} expired')
            return None
        except InvalidTokenError as ite:
            logger.exception(f'Invalid token {token}')
            return None