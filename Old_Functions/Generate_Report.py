from Key_Functions_Modules import *
from Database.DB_Connection import *
from UliPlot.XLSX import auto_adjust_xlsx_column_width

dupe_ip = dict()

def generate_report_main():
    with pd.ExcelWriter(f"Reports/{now_date}_Report.xlsx", mode='w') as writer:
        generate_legend_asset(writer)

    with pd.ExcelWriter(f"Reports/{now_date}_Report.xlsx", mode='a', if_sheet_exists='overlay') as writer: 
        generate_report_asset(writer)
        generate_report_cidr(writer)

def generate_report_cidr(writer):
    def apply_background_color(rows):
        if rows['cidr_used'] == "True":
            return ['background-color: green' for row in rows]
        else:
            return ['background-color: red' for row in rows]
        
    def align_center(rows):
        return ['text-align: center' for row in rows]
        
    cnxn, cursor = new_database_connection()
    print("Generating CIDR Report")
    
    query = ("""
        WITH used_cidr as (SELECT DISTINCT cidr.cidr_notation, count(cidr.cidr_notation) as ip_used,

		CASE WHEN cidr_notation is not NULL
		THEN 'True'
		else 'Else'
		END AS cidr_used

		FROM snow_cmdb_list as snow
		
		LEFT JOIN cidr_list as cidr
        ON snow.snow_computer_ip_address = cidr_ip_address

        LEFT JOIN crowdstrike as crowd
        ON snow.snow_computer_ip_address = crowd.[Local_IP]

		WHERE cidr_notation is not NULL
		
		GROUP BY cidr.cidr_notation),

        not_used_cidr as (SELECT DISTINCT cidr_notation, '0' as ip_used,

		CASE WHEN cidr_notation is not NULL
        THEN 'False'
        ELSE 'True'
		END AS cidr_used

        FROM cidr_list WHERE NOT EXISTS
        (SELECT cidr_notation FROM used_cidr WHERE cidr_list.cidr_notation = used_cidr.cidr_notation)
		
		GROUP BY cidr_notation)

        SELECT DISTINCT * FROM used_cidr UNION SELECT DISTINCT * FROM not_used_cidr""")

    df = pd.read_sql_query(query, cnxn)

    for column in df.columns:
        for index in df.index:
            try:
                if column == 'cidr_notation' and df[column][index] != None and len(df[column][index]) > 80:
                    df['cidr_notation'][index] = decrypt_data(df['cidr_notation'][index])

            except InvalidToken:
                pass


    df.style.apply(align_center, axis=0).apply(apply_background_color, axis=1).to_excel(writer, sheet_name=f"CIDR Report", engine='openpyxl')
    auto_adjust_xlsx_column_width(df, writer, sheet_name="CIDR Report", margin=0)


def generate_legend_asset(writer):

    def apply_background_color(rows):
        colors = ['green', 'orange', 'lightblue', 'red']
        for color in colors:
            return [f'background-color: {color}' for row in rows]

    legend = pd.DataFrame({"Legend" : ['Green','Orange','LightBlue','Red'], 'Description' : ["Trusted : Snow and Crowdstrike IP and Serial # Matches", "Semi-Trust : Snow and Crowdstrike IP and Serial # Matches / Last Discovered greater than 30 days and less than 90 days", "Dupe : SNOW ip address is duped", "Untrusted : Only found in SNOW unable to compare"]})
    legend.to_excel(writer, sheet_name=f"Asset Report", engine='openpyxl')

def generate_report_asset(writer):
    global dupe_ip
    
    def compare_two_dates(present, past):
        return past < present

    def dict_update(value, key):
        return dupe_ip.update({value : key})
    
    def align_center(rows):
        return ['text-align: center' for row in rows]
    
    def check_if_dupe(ip_address, date):
        if ip_address in dupe_ip.keys():
            if compare_two_dates(date, dupe_ip.get(ip_address)):
                dict_update(ip_address, date)
                return True
            
        else:
            dict_update(ip_address, date)
            return False
    
    def apply_background_color(rows):
        duped = check_if_dupe(rows['snow_computer_ip_address'], rows['last_discovered'])

        if int(rows['total_days']) < 30 \
        and rows['crowdstrike_found'] == "True" \
        and rows['snow_serial_number'].lower() == rows['Serial_Number'].lower():
            return ['background-color: green' for row in rows]
        
        elif int(rows['total_days']) <= 90 \
        and rows['crowdstrike_found'] == "True":
            return ['background-color: orange' for row in rows]
        
        elif int(rows['total_days']) <= 15 \
        and duped\
        and rows['crowdstrike_found'] == "False":
            return ['background-color: lightblue' for row in rows]
        
        else:
            return ['background-color: red' for row in rows]
        
    cnxn, cursor = new_database_connection()

    query = ("""
        SELECT DISTINCT cidr.*, snow.*, crowd.Hostname, crowd.[Platform], crowd.Model, crowd.[Local_IP], 
        crowd.Domain, crowd.[MAC_Address], crowd.[Host_ID], crowd.[Serial_Number],

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
        ON snow.snow_serial_number = crowd.[Serial_Number]

        ORDER BY cidr.cidr_notation DESC""")
    
    df = pd.read_sql_query(query, cnxn)

    for column in df.columns:
        for index in df.index:
            try:
                if df[column][index] != None and len(df[column][index]) > 80:
                    df[column][index] = decrypt_data(df[column][index])

            except InvalidToken:
                pass

    df.style.apply(align_center).apply(apply_background_color, axis=1).to_excel(writer, sheet_name=f"Asset Report", engine='openpyxl', startrow=5)
    auto_adjust_xlsx_column_width(df, writer, sheet_name="Asset Report", margin=0)