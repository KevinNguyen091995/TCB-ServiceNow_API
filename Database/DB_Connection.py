import configparser
import pyodbc


# Read the configuration file
config = configparser.ConfigParser()
config.read('Database/database.ini')

# Read the connection information from the file
server = config['DATABASE']['SERVER']
database = config['DATABASE']['DATABASE']
table_name = config['DATABASE']['TABLE']

try:
    # Connect to the database using Windows Authentication
    cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=' + server + ';DATABASE=' + database + ';Trusted_Connection=yes')
    cursor = cnxn.cursor()
    print("Connected to DB")

except Exception as e:
    print(e)

def commit(connection):
    # Commit the transaction
    try:
        connection.commit()
        
    except Exception as e:
        print(e + "\n Failed on committing data")

    print("Completed Commits Saved")