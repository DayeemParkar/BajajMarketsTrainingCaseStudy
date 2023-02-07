'''This file contains the DBConnection class'''

# for connecting db
import psycopg2
# for config vars
from config import DBVARS, CUSTOMER_TABLE, ACCOUNT_TABLE, TRANSACTION_TABLE, ACCOUNT_MAPPING_TABLE, CUSTOMER_TABLE_COLS, ACCOUNT_TABLE_COLS, ACCOUNT_MAPPING_TABLE_COLS, TRANSACTION_TABLE_COLS
# for logger
from logger_class import logger
from password_hash_class import PasswordHash


class DBConnection:
    '''Class containing methods to perform CRUD operations'''
    # class members
    conn = None
    cur = None
    _instance = None
    # db config vars
    account_mapping_table_constraints = (
        f"constraint fk_account foreign key ({ACCOUNT_MAPPING_TABLE_COLS[0][0]}) references {ACCOUNT_TABLE} ({ACCOUNT_TABLE_COLS[0][0]}) on delete cascade",
        f"constraint fk_customer foreign key ({ACCOUNT_MAPPING_TABLE_COLS[1][0]}) references {CUSTOMER_TABLE} ({CUSTOMER_TABLE_COLS[0][0]}) on delete cascade",
    )
    transaction_table_constraints = (
        f"constraint fk_account1 foreign key ({TRANSACTION_TABLE_COLS[1][0]}) references {ACCOUNT_TABLE} ({ACCOUNT_TABLE_COLS[0][0]}) on delete cascade",
        f"constraint fk_account2 foreign key ({TRANSACTION_TABLE_COLS[2][0]}) references {ACCOUNT_TABLE} ({ACCOUNT_TABLE_COLS[0][0]}) on delete cascade",
    )
    
    def __new__(cls):
        '''Override new to make it a singleton'''
        if not cls._instance:
            cls._instance = super(DBConnection, cls).__new__(cls)
        return cls._instance
    
    
    @classmethod
    def generateCreateQuery(cls, table_name, columns, constraints=None):
        '''Helper function to generate a create query'''
        query = f"CREATE TABLE IF NOT EXISTS {table_name} (" + ", ".join([f"{column[0]} {column[1]}" for column in columns])
        if constraints:
            query += ", " + ", ".join(constraints)
        return query + ");"
    
    
    @classmethod
    def generateInsertQuery(cls, table_name, params, columns=None):
        '''Helper function to generate an insert query'''
        query = f"INSERT INTO {table_name} "
        if columns:
            query += "(" + ", ".join([column[0] for column in columns]) + ") "
        return query + " VALUES (" + ", ".join(params) + ");"
        
    
    
    @classmethod
    def dbConnect(cls):
        '''Establish a connection to DB and create table if they don't exist'''
        try:
            if not cls.conn:
                cls.conn = psycopg2.connect(
                    database=DBVARS['database'],
                    user=DBVARS['user'],
                    password=DBVARS['password'],
                    host=DBVARS['host'],
                    port=DBVARS['port']
                )
                cls.cur = cls.conn.cursor()
        except psycopg2.Error as pe:
            logger.exception('Error while connecting to database')
    
    
    @classmethod
    def getConnection(cls):
        '''Return Connection object'''
        try:
            DBConnection.dbConnect()
            return cls.conn
        except psycopg2.Error as pe:
            logger.exception('Error while retrieving connection')
            return None
    
    
    @classmethod
    def createTables(cls):
        '''Create the required tables if they don't exist'''
        try:
            DBConnection.dbConnect()
            cls.cur.execute(cls.generateCreateQuery(CUSTOMER_TABLE, CUSTOMER_TABLE_COLS))
            cls.cur.execute(cls.generateCreateQuery(ACCOUNT_TABLE, ACCOUNT_TABLE_COLS))
            cls.cur.execute(cls.generateCreateQuery(ACCOUNT_MAPPING_TABLE, ACCOUNT_MAPPING_TABLE_COLS, cls.account_mapping_table_constraints))
            cls.cur.execute(cls.generateCreateQuery(TRANSACTION_TABLE, TRANSACTION_TABLE_COLS, cls.transaction_table_constraints))
            cls.conn.commit()
        except psycopg2.Error as pe:
            logger.exception('Error while creating tables')
    
    
    @classmethod
    def selectRows(cls, table_name, condition = None, additions = '', rows=None):
        '''Return rows from table'''
        try:
            DBConnection.dbConnect()
            DBConnection.createTables()
            select_rows = '*'
            if rows:
                select_rows = ', '.join(rows)
            if condition:
                cls.cur.execute(f"SELECT {select_rows} FROM {table_name} WHERE {condition} {additions};")
            else:
                cls.cur.execute(f"SELECT {select_rows} FROM {table_name} {additions};")
            rows = cls.cur.fetchall()
            return rows
        except psycopg2.Error as pe:
            logger.exception(f'Error while selecting rows of table {table_name}')
            return ()
    
    
    @classmethod
    def insertRow(cls, table_name, params, cols=None):
        '''Insert row into table'''
        try:
            DBConnection.dbConnect()
            DBConnection.createTables()
            if table_name == CUSTOMER_TABLE:
                cls.cur.execute(cls.generateInsertQuery(table_name, [f"'{param}'" for param in params], CUSTOMER_TABLE_COLS[1:]))
            elif table_name == ACCOUNT_TABLE:
                cls.cur.execute(cls.generateInsertQuery(table_name, [f"'{param}'" for param in params], ACCOUNT_TABLE_COLS[1:]))
            elif table_name == ACCOUNT_MAPPING_TABLE:
                cls.cur.execute(cls.generateInsertQuery(table_name, params))
            else:
                if cols:
                    cls.cur.execute(cls.generateInsertQuery(table_name, params, cols))
                else:
                    cls.cur.execute(cls.generateInsertQuery(table_name, params, TRANSACTION_TABLE_COLS[1:]))
            cls.conn.commit()
        except psycopg2.Error as pe:
            logger.exception(f'Error while inserting row with params {params} in table {table_name}')
    
    
    @classmethod
    def deleteRows(cls, table_name, condition=None):
        '''Delete rows from table'''
        try:
            DBConnection.dbConnect()
            DBConnection.createTables()
            if condition:
                cls.cur.execute(f"DELETE FROM {table_name} WHERE {condition};")
            cls.conn.commit()
        except psycopg2.Error as pe:
            logger.exception(f'Error while deleting rows from table {table_name} for condition {condition}')
    
    
    @classmethod
    def updateRow(cls, table_name, setCols=None, condition=None):
        '''Update row in table'''
        try:
            DBConnection.dbConnect()
            DBConnection.createTables()
            if setCols and condition:
                cls.cur.execute(f"UPDATE {table_name} SET {setCols} WHERE {condition};")
            cls.conn.commit()
        except psycopg2.Error as pe:
            logger.exception(f'Error while updating rows {setCols} of table {table_name} on condition {condition}')
    
    
    @classmethod
    def dropTable(cls, table_name):
        '''Drop table'''
        try:
            DBConnection.dbConnect()
            cls.cur.execute(f"DROP TABLE IF EXISTS {table_name};")
            cls.conn.commit()
        except psycopg2.Error as pe:
            logger.exception(f'Error while dropping table {table_name}')
    
    
    @classmethod
    def getTimeStamp(cls):
        '''Function to get current timestamp'''
        try:
            DBConnection.dbConnect()
            cls.cur.execute('select current_timestamp;')
            return cls.cur.fetchall()[0][0]
        except psycopg2.Error as pe:
            logger.exception('Error while retrieving current timestamp')
    
    
    @classmethod
    def closeDbConnection(cls):
        if cls.conn:
            cls.cur.close()
            cls.conn.close()
            cls.cur = None
            cls.conn = None


if __name__ == '__main__':
    DBConnection.dropTable(ACCOUNT_MAPPING_TABLE)
    DBConnection.dropTable(TRANSACTION_TABLE)
    DBConnection.dropTable(CUSTOMER_TABLE)
    DBConnection.dropTable(ACCOUNT_TABLE)
    DBConnection.insertRow(CUSTOMER_TABLE, ['uname', PasswordHash.generateHash('upass'), 'fname', 'lname', 'addr', '12345'])
    DBConnection.insertRow(ACCOUNT_TABLE, [PasswordHash.generateHash('a1pass'),'salary', '70000'])
    DBConnection.insertRow(ACCOUNT_TABLE, [PasswordHash.generateHash('a2pass'),'salary', '70000'])
    DBConnection.insertRow(ACCOUNT_MAPPING_TABLE, ['1','1'])
    DBConnection.insertRow(ACCOUNT_MAPPING_TABLE, ['2','1'])
    DBConnection.insertRow(TRANSACTION_TABLE, ['1', '2', '1000', f"'{DBConnection.getTimeStamp()}'"])
    DBConnection.insertRow(TRANSACTION_TABLE, ['1','1000', f"'{DBConnection.getTimeStamp()}'"], [TRANSACTION_TABLE_COLS[2], TRANSACTION_TABLE_COLS[3], TRANSACTION_TABLE_COLS[4]])
    # custpass = DBConnection.selectRows(CUSTOMER_TABLE, additions=f"ORDER BY {CUSTOMER_TABLE_COLS[1][0]}")[0][2]
    # accpass = DBConnection.selectRows(ACCOUNT_TABLE, condition=f"{ACCOUNT_TABLE_COLS[2][0]} = 'salary'")[0][1]
    # print(custpass)
    # print(accpass)
    # print(PasswordHash.verifyHash(custpass, 'upass'))
    # print(PasswordHash.verifyHash(accpass, 'apass'))
    # print(DBConnection.selectRows(ACCOUNT_MAPPING_TABLE))
    print(DBConnection.selectRows(TRANSACTION_TABLE))