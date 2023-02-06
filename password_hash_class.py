'''This file contains Password Hash Class'''

from flask_bcrypt import Bcrypt
from logger_class import logger


class PasswordHash():
    # class members
    _instance = None
    bcrypt = Bcrypt()
    
    
    def __new__(cls):
        '''Override new to make it a singleton'''
        if not cls._instance:
            cls._instance = super(PasswordHash, cls).__new__(cls)
        return cls._instance
    
    
    @classmethod
    def generateHash(cls, password):
        try:
            return str(cls.bcrypt.generate_password_hash(password), 'utf-8')
        except Exception as e:
            logger.exception('Error while generating password hash')
            return ''
    
    
    @classmethod
    def verifyHash(cls, password_hash, password):
        try:
            return cls.bcrypt.check_password_hash(bytes(password_hash, 'utf-8'), password)
        except Exception as e:
            logger.exception('Error while verifying password')
            return False