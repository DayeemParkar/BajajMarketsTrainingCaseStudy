'''This file contains the DBConnection class'''

# for connecting db
import psycopg2
# for config vars
from config import DBVARS, CUSTOMER_TABLE, ACCOUNT_TABLE, ACCOUNT_MAPPING_TABLE, CUSTOMER_TABLE_COLS, ACCOUNT_TABLE_COLS, ACCOUNT_MAPPING_TABLE_COLS


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
        if not cls.conn:
            cls.conn = psycopg2.connect(
                database=DBVARS['database'],
                user=DBVARS['user'],
                password=DBVARS['password'],
                host=DBVARS['host'],
                port=DBVARS['port']
            )
            cls.cur = cls.conn.cursor()
    
    
    @classmethod
    def getConnection(cls):
        '''Return Connection object'''
        DBConnection.dbConnect()
        return cls.conn
    
    
    @classmethod
    def createTables(cls):
        '''Create the required tables if they don't exist'''
        DBConnection.dbConnect()
        cls.cur.execute(cls.generateCreateQuery(CUSTOMER_TABLE, CUSTOMER_TABLE_COLS))
        cls.cur.execute(cls.generateCreateQuery(ACCOUNT_TABLE, ACCOUNT_TABLE_COLS))
        cls.cur.execute(cls.generateCreateQuery(ACCOUNT_MAPPING_TABLE, ACCOUNT_MAPPING_TABLE_COLS, cls.account_mapping_table_constraints))
        cls.conn.commit()
    
    
    @classmethod
    def selectRows(cls, table_name, condition = None, additions = ''):
        '''Return rows from table'''
        DBConnection.dbConnect()
        DBConnection.createTables()
        if condition:
            cls.cur.execute(f"SELECT * FROM {table_name} WHERE {condition} {additions};")
        else:
            cls.cur.execute(f"SELECT * FROM {table_name} {additions};")
        rows = cls.cur.fetchall()
        return rows
    
    
    @classmethod
    def insertRow(cls, table_name, params):
        '''Insert row into table'''
        DBConnection.dbConnect()
        DBConnection.createTables()
        if table_name == CUSTOMER_TABLE:
            cls.cur.execute(cls.generateInsertQuery(table_name, [f"'{param}'" for param in params], CUSTOMER_TABLE_COLS[1:]))
        elif table_name == ACCOUNT_TABLE:
            cls.cur.execute(cls.generateInsertQuery(table_name, [f"'{param}'" for param in params], ACCOUNT_TABLE_COLS[1:]))
        else:
            cls.cur.execute(cls.generateInsertQuery(table_name, params))
        cls.conn.commit()
    
    
    @classmethod
    def deleteRows(cls, tname, condition=None):
        '''Delete rows from table'''
        DBConnection.dbConnect()
        DBConnection.createTables()
        if condition:
            cls.cur.execute(f"DELETE FROM {tname} WHERE {condition};")
        cls.conn.commit()
    
    
    @classmethod
    def updateRow(cls, tname, setCols=None, condition=None):
        '''Update row in table'''
        DBConnection.dbConnect()
        DBConnection.createTables()
        if setCols and condition:
            cls.cur.execute(f"UPDATE {tname} SET {setCols} WHERE {condition}")
        cls.conn.commit()
    
    
    @classmethod
    def dropTable(cls, tname):
        '''Drop table'''
        DBConnection.dbConnect()
        cls.cur.execute(f"DROP TABLE IF EXISTS {tname};")
        cls.conn.commit()
    
    
    @classmethod
    def closeDbConnection(cls):
        if cls.conn:
            cls.cur.close()
            cls.conn.close()
            cls.cur = None
            cls.conn = None

# DBConnection.dropTable(ACCOUNT_MAPPING_TABLE)
# DBConnection.dropTable(CUSTOMER_TABLE)
# DBConnection.dropTable(ACCOUNT_TABLE)
# DBConnection.insertRow(CUSTOMER_TABLE, ['uname', 'fname', 'lname', 'addr', '12345'])
# DBConnection.insertRow(ACCOUNT_TABLE, ['salary', '70000'])
# DBConnection.insertRow(ACCOUNT_MAPPING_TABLE, ['1','1'])
# print(DBConnection.selectRows(CUSTOMER_TABLE, additions=f"ORDER BY {CUSTOMER_TABLE_COLS[1][0]}"))
# print(DBConnection.selectRows(ACCOUNT_TABLE, condition=f"{ACCOUNT_TABLE_COLS[1][0]} = 'salary'"))
# print(DBConnection.selectRows(ACCOUNT_MAPPING_TABLE))