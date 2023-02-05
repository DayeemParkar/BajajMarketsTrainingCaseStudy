import logging
import os

class Logger:
    logger = None
    ch = None
    _instance = None
    
    def __new__(cls):
        '''Override new to make it a singleton'''
        if not cls._instance:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance
    
    @classmethod
    def makeLogger(cls):
        '''Make a logger object'''
        if not cls.logger:
            cls.logger = logging.getLogger('__name__')
            cls.logger.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            fh = logging.FileHandler(os.getcwd() + '/LogFiles/bankLog.log')
            fh.setFormatter(formatter)
            ch = logging.StreamHandler()
            ch.setFormatter(formatter)
            cls.logger.addHandler(fh)
            cls.logger.addHandler(ch)
    
    @classmethod
    def getLogger(cls):
        '''Make a logger object if it doesnt exist and return it'''
        cls.makeLogger()
        return cls.logger

logger = Logger.getLogger()