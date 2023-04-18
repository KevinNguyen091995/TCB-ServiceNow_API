import configparser
import pyodbc


#ConfigParser Setup
config = configparser.ConfigParser()
config.read('C:/Users/kenguy/OneDrive - Texas Capital Bank/Desktop/Python/Config_Properties/config_file.txt')

# Read the connection information from the file
server = config['DATABASE']['SERVER']
database = config['DATABASE']['DATABASE']

def new_database_connection():
    try:
        # Connect to the database using Windows Authentication
        cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=' + server + ';DATABASE=' + database + ';Trusted_Connection=yes')
        cursor = cnxn.cursor()

        return cnxn, cursor

    except Exception as e:
        print("Failed to connect to database" , "\n", e)