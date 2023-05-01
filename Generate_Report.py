from Key_Functions_Modules import *
from Database.DB_Connection import *
from UliPlot.XLSX import auto_adjust_xlsx_column_width

def align_center(x):
    return ['text-align: center' for x in x]

def generate_report_main():
    with pd.ExcelWriter(f"Reports/{now_date}_Report.xlsx") as writer:
        generate_report_asset(writer)
        generate_report_cidr(writer)

def generate_report_cidr(writer):
    cnxn, cursor = new_database_connection()
    
    query = ("""WITH used_cidr as (SELECT DISTINCT cidr.cidr_notation,

		CASE WHEN cidr_notation is not NULL
		THEN 'True'
		else 'Else'
		END AS cidr_used

		FROM snow_cmdb_list as snow
		
		LEFT JOIN cidr_list as cidr
        ON snow.snow_computer_ip_address = cidr_ip_address

        LEFT JOIN crowdstrike as crowd
        ON snow.snow_computer_ip_address = crowd.[Local IP]

		WHERE cidr_notation is not NULL),

        not_used_cidr as (SELECT DISTINCT cidr_notation,

                CASE WHEN cidr_notation is not NULL
                THEN 'False'
                else 'True'
                END AS cidr_used

        FROM cidr_list WHERE NOT EXISTS
        (SELECT cidr_notation FROM used_cidr WHERE cidr_list.cidr_notation = used_cidr.cidr_notation))

        SELECT DISTINCT * FROM used_cidr UNION SELECT DISTINCT * FROM not_used_cidr""")

    df = pd.read_sql_query(query, cnxn)

    for column in df.columns:
        for index in df.index:
            try:
                if df.loc[index][column] != None and len(df.loc[index][column]) > 80:
                    df.loc[index][column] = decrypt_data(df.loc[index][column])

            except InvalidToken:
                pass

    df.style.apply(align_center, axis=0).to_excel(writer, sheet_name=f"CIDR Report", engine='openpyxl')
    auto_adjust_xlsx_column_width(df, writer, sheet_name="CIDR Report", margin=0)


def generate_report_asset(writer):
    cnxn, cursor = new_database_connection()

    query = ("""
        SELECT DISTINCT cidr.*, snow.*, crowd.Hostname, crowd.[Platform], crowd.Model, crowd.[Local IP], 
        crowd.Domain, crowd.[MAC Address], crowd.[Host ID], crowd.[Serial Number],

		CASE when crowd.Hostname is NULL or crowd.Hostname = '' 
		THEN 'False'
		else 'True'
		END AS crowdstrike_found,

		CASE when crowd.Hostname is NULL or crowd.Hostname = '' 
		and cidr.cidr_ip_address is NULL or cidr.cidr_ip_address = ''
		THEN 'False'
		else 'True'
		END AS cidr_crowd_found,

		CASE when snow.snow_computer_name is NULL or snow.snow_computer_name = '' 
		THEN 'False'
		else 'True'
		END AS snow_found

		FROM snow_cmdb_list as snow
		
		LEFT JOIN cidr_list as cidr
        ON snow.snow_computer_ip_address = cidr_ip_address

        LEFT JOIN crowdstrike as crowd
        ON snow.snow_computer_ip_address = crowd.[Local IP]

        ORDER BY cidr.cidr_notation DESC""")

    df = pd.read_sql_query(query, cnxn)

    for column in df.columns:
        for index in df.index:
            try:
                if df.loc[index][column] != None and len(df.loc[index][column]) > 80:
                    df.loc[index][column] = decrypt_data(df.loc[index][column])

            except InvalidToken:
                pass

    df.style.apply(align_center, axis=0).to_excel(writer, sheet_name=f"Asset Report", engine='openpyxl')
    auto_adjust_xlsx_column_width(df, writer, sheet_name="Asset Report", margin=0)