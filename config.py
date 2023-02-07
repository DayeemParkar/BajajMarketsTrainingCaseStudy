'''This file contains objects retrieved from .env file'''

from dotenv import load_dotenv
from pathlib import Path
from ast import literal_eval
import os

dotenv_path = Path('config.env')
load_dotenv(dotenv_path=dotenv_path)

# app config
SECRET_KEY = os.getenv('SECRET_KEY')

# swagger config
SWAGGER_URL = os.getenv('SWAGGER_URL')
API_URL = os.getenv('API_URL')
SWAGGER_BLUEPRINT_CONFIG = literal_eval(os.getenv('SWAGGER_BLUEPRINT_CONFIG'))

# session config
USERNAME = os.getenv('USERNAME')
TOKEN = os.getenv('TOKEN')

# database config
DBVARS = literal_eval(os.getenv('DBVARS'))
CUSTOMER_TABLE = os.getenv('CUSTOMER_TABLE')
ACCOUNT_TABLE = os.getenv('ACCOUNT_TABLE')
ACCOUNT_MAPPING_TABLE = os.getenv('ACCOUNT_MAPPING_TABLE')
TRANSACTION_TABLE = os.getenv('TRANSACTION_TABLE')
CUSTOMER_TABLE_COLS = literal_eval(os.getenv('CUSTOMER_TABLE_COLS'))
ACCOUNT_TABLE_COLS = literal_eval(os.getenv('ACCOUNT_TABLE_COLS'))
ACCOUNT_MAPPING_TABLE_COLS = literal_eval(os.getenv('ACCOUNT_MAPPING_TABLE_COLS'))
TRANSACTION_TABLE_COLS = literal_eval(os.getenv('TRANSACTION_TABLE_COLS'))

# print(SECRET_KEY)
# print(SWAGGER_URL)
# print(API_URL)
# print(SWAGGER_BLUEPRINT_CONFIG)
# print(USERNAME)
# print(TOKEN)
# print(DBVARS)
# print(CUSTOMER_TABLE)
# print(ACCOUNT_TABLE)
# print(ACCOUNT_MAPPING_TABLE)
# print(CUSTOMER_TABLE_COLS)
# print(ACCOUNT_TABLE_COLS)
# print(ACCOUNT_MAPPING_TABLE_COLS)
# print(TRANSACTION_TABLE)
# print(TRANSACTION_TABLE_COLS)