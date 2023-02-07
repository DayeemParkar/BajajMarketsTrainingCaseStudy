from flask import Flask
from logger_class import logger
# for Password Hash class
from password_hash_class import PasswordHash
# for DB
from db_connector_class import DBConnection
# for secret_key
from config import *

from forms import AccountForm

from helpers import *

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
    
def tryToAddAccount(form):
    '''Function to add a new customer to database'''
    try:
        account_type = form.account_type.data

        password = form.password.data
        password_hash = PasswordHash.generateHash(password)
        if len(password_hash) == 0:
            return (False, f'Bad password {password}. Use another password.')
        
        balance = form.balance.data
        
        params = [password, account_type, balance]
        DBConnection.insertRow(ACCOUNT_TABLE, params)
        return (True)
    except Exception as e:
        logger.exception(f'Error while trying to adding account: {account_type}, {password}, {balance}')
        return (False, 'Error while trying to sign up. Please try again')



def tryToViewTransactionHistory(account_no):
    '''Function to add a new customer to database'''
    try:
        rows = DBConnection.selectRows(table_name=TRANSACTION_TABLE, condition=f"{TRANSACTION_TABLE_COLS[1][0]} = '{account_no}'")
        res = []
        for row in rows:
            ans = [row[0]]
            if account_no == row[1]:
               
                ans.append(row[1])
                ans.append('NULL')
                ans.append(row[3])
            else:
                ans.append(row[2])
                ans.append(row[3])
                ans.append('NULL')
            
            ans.append(row[4])
            
            res.append(ans)
        return res
            
    except Exception as e:
        return (False, 'Error while trying to view transaction history. Please try again')



def tryToViewAccounts(customer_id):
    DBConnection.dbConnect()
    cur = DBConnection.cur
    sql = f"SELECT account_no, account_type, account_balance from {ACCOUNT_TABLE} where account_no in (select account_no from {ACCOUNT_MAPPING_TABLE} where customer_id = '{customer_id}')"
    
    cur.execute(sql)
    return cur.fetchall()
    

def checkIfAccountExists(account_no):
    '''Function to check if account is unique by checking if an entry exists in DB'''
    rows = DBConnection.selectRows(table_name=ACCOUNT_TABLE, condition=f"{ACCOUNT_TABLE_COLS[0][0]} = '{account_no}'")
    return (len(rows) != 0, rows)


    
def tryToMakeTransaction(from_account_no, to_account_no, amount):
    try:
        res1 = checkIfAccountExists(from_account_no)
        res2 = checkIfAccountExists(to_account_no)
        if not (res1[0] and res2[0]):
            return (False, "Cannot make trasation")
        from_account_row = res1[1][0]
        to_account_row = res2[1][0]
        from_balance = int(from_account_row[3])
        to_balance = int(to_account_row[3])
        
        if from_balance <= amount:
            return(False, "Not Enough Balance")
        
        new_from_amount = from_balance - amount
        new_to_amount = to_balance + amount
        
        
        DBConnection.updateRow(ACCOUNT_TABLE, f"{ACCOUNT_TABLE_COLS[3][0]} = '{new_from_amount}'", f"{ACCOUNT_TABLE_COLS[0][0]} = {from_account_no}")
        
        DBConnection.updateRow(ACCOUNT_TABLE, f"{ACCOUNT_TABLE_COLS[3][0]} = '{new_to_amount}'", f"{ACCOUNT_TABLE_COLS[0][0]} = {to_account_no}")
        
        DBConnection.insertRow(TRANSACTION_TABLE, params=[from_account_no, to_account_no, f"{amount}", f"'{DBConnection.getTimeStamp()}'"])
        
    except Exception as e:
        print(f'{e}')
        return (False, 'Error Making Transaction. Please try again')


def tryToMakeDeposit(account_no, amount):
    try:
        res = checkIfAccountExists(account_no)
        if not (res[0]):
            return (False, "Cannot make trasation")
        account_row = res[1][0]
        balance = int(account_row[3])
        
        new_amount = balance + amount
        DBConnection.updateRow(ACCOUNT_TABLE, f"{ACCOUNT_TABLE_COLS[3][0]} = '{new_amount}'", f"{ACCOUNT_TABLE_COLS[0][0]} = {account_no}")
        
        
        DBConnection.insertRow(TRANSACTION_TABLE, params=['NULL', account_no, f"{amount}", f"'{DBConnection.getTimeStamp()}'"])
        
    except Exception as e:
        print(f'{e}')
        return (False, 'Error Making Transaction. Please try again')
  

def tryToMakeWithdrawal(account_no, amount):
    try:
        res = checkIfAccountExists(account_no)
        if not (res[0]):
            return (False, "Cannot make trasation")
        account_row = res[1][0]
        balance = int(account_row[3])
        
        if balance < amount:
            return(False, "Not Enough Balance")
        
        new_amount = balance - amount
        DBConnection.updateRow(ACCOUNT_TABLE, f"{ACCOUNT_TABLE_COLS[3][0]} = '{new_amount}'", f"{ACCOUNT_TABLE_COLS[0][0]} = {account_no}")
        
        
        DBConnection.insertRow(TRANSACTION_TABLE, params=[account_no, 'NULL', f"{amount}", f"'{DBConnection.getTimeStamp()}'"])
        
    except Exception as e:
        print(f'{e}')
        return (False, 'Error Making Transaction. Please try again')
    
    
    
def modifyCustomer(form):
    try:
        customer_id = form.customer_id.data
        password = form.password.data
        password_hash = PasswordHash.generateHash(password)
        if len(password_hash) == 0:
            return (False, f'Bad password {password}. Use another password.')
        address = form.address.data
        mobile_number = form.mobile_number.data
        if mobile_number // 10000000000 <= 0 and mobile_number // 10000000000 > 9:
            return (False, f'Invalid mobile number {mobile_number}. Enter a valid mobile number')
        if not checkIfMobileIsUnique(mobile_number):
            return (False, f'Mobile number {mobile_number} already registered')
        
        set_cols = f"{CUSTOMER_TABLE_COLS[2][0]} = '{password}', {CUSTOMER_TABLE_COLS[5][0]} = '{address}', {CUSTOMER_TABLE_COLS[6][0]} = '{mobile_number}'"
        DBConnection.updateRow(CUSTOMER_TABLE,setCols=set_cols, condition=f"{CUSTOMER_TABLE_COLS[0][0]} = {customer_id}")
        
    except Exception as e:
        print(f'{e}')
        return (False, 'Error Making Transaction. Please try again')
    

def deleteCustomer(customer_id):
    try:
        DBConnection.deleteRows(CUSTOMER_TABLE, condition=f"{CUSTOMER_TABLE_COLS[0][0]} = {customer_id}")
        
    except Exception as e:
        print(f'{e}')
        return (False, 'Error Making Transaction. Please try again')
 
    
def modifyAccount(form):
    try:
        account_no = form.account_no.data
        password = form.password.data
        password_hash = PasswordHash.generateHash(password)
        if len(password_hash) == 0:
            return (False, f'Bad password {password}. Use another password.')
        
        set_cols = f"{ACCOUNT_TABLE_COLS[1][0]} = '{password}'"
        DBConnection.updateRow(ACCOUNT_TABLE, setCols=set_cols, condition=f"{ACCOUNT_TABLE_COLS[0][0]} = {account_no}")
        
    except Exception as e:
        print(f'{e}')
        return (False, 'Error Making Transaction. Please try again')
    

def deleteAccount(account_no):
    try:
        DBConnection.deleteRows(ACCOUNT_TABLE, condition=f"{ACCOUNT_TABLE_COLS[0][0]} = {account_no}")
        
    except Exception as e:
        print(f'{e}')
        return (False, 'Error Making Transaction. Please try again')
    
    
    
def displayTransactions():
    return DBConnection.selectRows(TRANSACTION_TABLE)

def displayCustomers():
    return DBConnection.selectRows(CUSTOMER_TABLE)

def displayAccount():
    return DBConnection.selectRows(ACCOUNT_TABLE)


@app.route('/')
def home():
    DBConnection.dropTable(ACCOUNT_MAPPING_TABLE)
    DBConnection.dropTable(TRANSACTION_TABLE)
    DBConnection.dropTable(CUSTOMER_TABLE)
    DBConnection.dropTable(ACCOUNT_TABLE)
    DBConnection.insertRow(CUSTOMER_TABLE, ['uname', PasswordHash.generateHash('upass'), 'fname', 'lname', 'addr', '12345'])
    DBConnection.insertRow(ACCOUNT_TABLE, [PasswordHash.generateHash('apass'),'salary', '70000'])
    DBConnection.insertRow(ACCOUNT_TABLE, [PasswordHash.generateHash('a2pass'),'salary', '80000'])
    DBConnection.insertRow(ACCOUNT_MAPPING_TABLE, ['1','1'])
    DBConnection.insertRow(ACCOUNT_MAPPING_TABLE, ['2','1'])
    #DBConnection.insertRow(TRANSACTION_TABLE, ['1', '2', '1000', f"'{DBConnection.getTimeStamp()}'"])
    custpass = DBConnection.selectRows(CUSTOMER_TABLE, additions=f"ORDER BY {CUSTOMER_TABLE_COLS[1][0]}")[0][2]
    accpass = DBConnection.selectRows(ACCOUNT_TABLE, condition=f"{ACCOUNT_TABLE_COLS[2][0]} = 'salary'")[0][1]
    print(custpass)
    print(accpass)
    print(PasswordHash.verifyHash(custpass, 'upass'))
    print(PasswordHash.verifyHash(accpass, 'apass'))
    print(DBConnection.selectRows(ACCOUNT_MAPPING_TABLE))
    tryToMakeTransaction('1','2',2000000000)
    print(DBConnection.selectRows(TRANSACTION_TABLE))
    print(tryToViewTransactionHistory("1"))
    print(tryToViewAccounts("1"))
    return 'Test'
app.run()