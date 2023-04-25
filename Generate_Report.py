from Key_Functions_Modules import *
from Database.DB_Connection import *

def generate_report():
    cnxn, cursor = new_database_connection()
    columns = []

    query = ("""
        SELECT DISTINCT cidr.*, snow.*, crowd.Hostname, crowd.[Platform], crowd.Model, crowd.[Local IP], 
        crowd.Domain, crowd.[MAC Address], crowd.[Host ID], crowd.[Serial Number] FROM snow_cmdb_list as snow

        LEFT JOIN cidr_list as cidr
        ON snow.snow_computer_ip_address = cidr_ip_address

        LEFT JOIN crowdstrike as crowd
        ON snow.snow_computer_ip_address = crowd.[Local IP]

        ORDER BY cidr.cidr_notation DESC""")
    
    df = pd.read_sql_query(query, cnxn)

    for column in df.columns:
        for data in df[column]:
            if data != None and len(data) > 60:
                try:
                    df[column] = decrypt_data(data)
                except InvalidToken:
                        pass
                
            elif data == None:
                 df.style.apply('background-color: yellow')
    
                 
                
    df.to_excel("test12321321.xlsx")