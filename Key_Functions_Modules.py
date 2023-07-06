from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from datetime import datetime, timedelta
from UliPlot.XLSX import auto_adjust_xlsx_column_width
from time import time, sleep
from openpyxl import Workbook, load_workbook
from collections import OrderedDict
import Database.DB_Connection as DC
import pandas as pd
import subprocess
import socket
import configparser
import asyncio
import csv
import threading
import os
import json
import math
import pysnow

#ConfigParser Setup
config = configparser.ConfigParser()
config.read('C:/Users/kenguy/OneDrive - Texas Capital Bank/Desktop/Python/Config_Properties/config_file.txt')

#DEFAULT
username = config.get('DEFAULT', 'username')
password = config.get('DEFAULT', 'password')
instance_dev = config.get('DEFAULT', 'instance_dev')
instance_test = config.get('DEFAULT', 'instance_test')
instance = config.get('DEFAULT', 'instance')

#Key
key = config.get('DEFAULT', 'key')

#Data key Encryption
data_key = Fernet(key)

#Now Date Time
now_date = datetime.now().strftime("%Y-%m-%d")

#Initial Pandas Data
computer_dataframe = pd.DataFrame()
window_dataframe = pd.DataFrame()
linux_dataframe = pd.DataFrame()
esx_dataframe = pd.DataFrame()
cloud_dataframe= pd.DataFrame()
vmware_dataframe = pd.DataFrame()
cisco_firewall_dataframe = pd.DataFrame()
palo_firewall_dataframe = pd.DataFrame()
ip_firewall_dataframe = pd.DataFrame()
ip_router_dataframe = pd.DataFrame()
ip_switch_dataframe = pd.DataFrame()
netgear_dataframe = pd.DataFrame()
wireless_ap_dataframe = pd.DataFrame()
class_count_mapping = dict()
field_count_mapping = dict()
total_count_mapping = dict()

#Mapping
operational_status_mapping = {
    '1' : 'Operational',
    '2' : 'Non-Operational',
    '6' : 'Retired'
}

install_status_mapping = {
    '1' : 'Installed',
    '7' : 'Retired'
}
software_mapping = dict({
    "cmdb_ci_computer" : [],
    "cmdb_ci_win_server" : [],
    "cmdb_ci_linux_server" : [],
    "cmdb_ci_esx_server" : [],
})

#Initial Arrays API List
excel_list = ['cmdb_ci_computer', 'cmdb_ci_win_server', 'cmdb_ci_linux_server', 'cmdb_ci_esx_server']
compare_list = ["cmdb_ci_linux_server", "cmdb_ci_win_server", 'cmdb_ci_vm_instance', 'cmdb_ci_vmware_instance', 'cmdb_ci_computer']
software_list_linux = ['cmdb_ci_linux_server', 'cmdb_ci_unix_server', 'cmdb_ci_esx_server']
software_list_windows = ['cmdb_ci_win_server', 'cmdb_ci_computer']

#Initial Global Data for Vulnerability Scans
software = dict()
owners = []
vul_entry_dict = dict()
vul_active_count = dict()
vul_inactive_count = dict()

#ConfigParser Setup
config = configparser.ConfigParser()
config.read('C:/Users/kenguy/OneDrive - Texas Capital Bank/Desktop/Python/Config_Properties/config_file.txt')

#DEFAULT
username = config.get('DEFAULT', 'username')
password = config.get('DEFAULT', 'password')
instance_dev = config.get('DEFAULT', 'instance_dev')
instance_test = config.get('DEFAULT', 'instance_test')
instance = config.get('DEFAULT', 'instance')

#Key
key = config.get('DEFAULT', 'key')

#Datakey
data_key = Fernet(key)

#Path
path = f"Reports/{now_date}"

#DateTime
now_date = datetime.now().strftime("%Y-%m-%d")

#Create client object
c = pysnow.Client(instance=instance, user=username, password=password)

#API Setup
sys_user_api = config.get('API', 'sys_user')
incident_api = config.get('API', 'incident')
software_api = config.get('API', 'software_install')
vulnerability_ci_api = config.get('API', 'vulnerability_ci')
vulnerability_item_api = config.get('API', 'vulnerability_item') 
vulnerability_entry_api = config.get('API', 'vulnerability_entry')
sys_object_api = config.get('API', 'sys_object')
sys_user_group_api = config.get('API', 'sys_user_group')
cmdb_ci_computer_api = config.get('API', 'cmdb_ci_computer')
cmdb_ci_server_api = config.get("API", 'cmdb_ci_server')
cmdb_ci_win_server_api = config.get("API", 'cmdb_ci_win_server')
cmdb_ci_linux_server_api = config.get("API", 'cmdb_ci_linux_server')
cmdb_ci_unix_server_api = config.get("API", 'cmdb_ci_unix_server')
cmdb_ci_esx_server_api = config.get("API", 'cmdb_ci_esx_server')
cmdb_sam_sw_install_api = config.get("API", "cmdb_sam_sw_install")
cmn_location_api = config.get("API", "cmn_location")
cmdb_ci_vm_instance_api = config.get("API", "cmdb_ci_vm_instance")
cmdb_ci_netgear_api = config.get("API", "cmdb_ci_netgear")

# Define a resource, here we'll use the incident table API
sys_user = c.resource(api_path=sys_user_api)
incident = c.resource(api_path=incident_api)
software_install = c.resource(api_path=software_api)
vulnerability_ci = c.resource(api_path=vulnerability_ci_api)
sys_object = c.resource(api_path=sys_object_api)
vulnerability_item = c.resource(api_path=vulnerability_item_api)
vulnerability_entry = c.resource(api_path=vulnerability_entry_api)
sys_user_group = c.resource(api_path=sys_user_group_api)
cmdb_ci_computer = c.resource(api_path=cmdb_ci_computer_api)
cmdb_ci_server_list = c.resource(api_path=cmdb_ci_server_api)
cmdb_ci_win_server = c.resource(api_path=cmdb_ci_win_server_api)
cmdb_ci_linux_server = c.resource(api_path=cmdb_ci_linux_server_api)
cmdb_ci_unix_server = c.resource(api_path=cmdb_ci_unix_server_api)
cmdb_ci_esx_server = c.resource(api_path=cmdb_ci_esx_server_api)
cmdb_sam_sw_install = c.resource(api_path=cmdb_sam_sw_install_api)
cmn_location = c.resource(api_path=cmn_location_api)
cmdb_ci_vm_instance = c.resource(api_path=cmdb_ci_vm_instance_api)
cmdb_ci_netgear = c.resource(api_path=cmdb_ci_netgear_api)

def set_computer_dataframe(data):
    global computer_dataframe

    computer_dataframe = pd.concat([computer_dataframe, pd.DataFrame(pd.json_normalize(data))])

    return computer_dataframe

def get_computer_dataframe():
    return computer_dataframe

def set_window_dataframe(data):
    global window_dataframe

    window_dataframe = pd.concat([window_dataframe, pd.DataFrame(pd.json_normalize(data))])

    return window_dataframe

def get_window_dataframe():
    return window_dataframe

def set_linux_dataframe(data):
    global linux_dataframe

    linux_dataframe = pd.concat([linux_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_linux_dataframe():
    return linux_dataframe

def set_esx_dataframe(data):
    global esx_dataframe

    esx_dataframe = pd.concat([esx_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_esx_dataframe():
    return esx_dataframe

def set_cloud_dataframe(data):
    global cloud_dataframe

    cloud_dataframe = pd.concat([cloud_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_cloud_dataframe():
    return cloud_dataframe

def set_vmware_dataframe(data):
    global vmware_dataframe

    vmware_dataframe = pd.concat([vmware_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_vmware_dataframe():
    return vmware_dataframe

def set_cisco_firewall_dataframe(data):
    global cisco_firewall_dataframe

    cisco_firewall_dataframe = pd.concat([cisco_firewall_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_cisco_firewall_dataframe():
    return cisco_firewall_dataframe

def set_palo_firewall_dataframe(data):
    global palo_firewall_dataframe

    palo_firewall_dataframe = pd.concat([palo_firewall_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_palo_firewall_dataframe():
    return palo_firewall_dataframe

def set_ip_firewall_dataframe(data):
    global palo_firewall_dataframe

    palo_firewall_dataframe = pd.concat([palo_firewall_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_ip_firewall_dataframe():
    return palo_firewall_dataframe

def set_ip_router_dataframe(data):
    global ip_router_dataframe

    ip_router_dataframe = pd.concat([ip_router_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_ip_router_dataframe():
    return ip_router_dataframe

def set_ip_switch_dataframe(data):
    global ip_switch_dataframe

    ip_switch_dataframe = pd.concat([ip_switch_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_ip_switch_dataframe():
    return ip_switch_dataframe

def set_netgear_dataframe(data):
    global netgear_dataframe

    netgear_dataframe = pd.concat([netgear_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_netgear_dataframe():
    return netgear_dataframe

def set_wireless_ap_dataframe(data):
    global wireless_ap_dataframe

    wireless_ap_dataframe = pd.concat([wireless_ap_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_wireless_ap_dataframe():
    return wireless_ap_dataframe

cmdb_mapping = {
    "cmdb_ci_computer" : set_computer_dataframe,
    "cmdb_ci_win_server" : set_window_dataframe,
    "cmdb_ci_linux_server" : set_linux_dataframe,
    "cmdb_ci_esx_server" : set_esx_dataframe,
    "cmdb_ci_vm_instance" : set_cloud_dataframe,
    "cmdb_ci_vmware_instance" : set_vmware_dataframe,
    "cmdb_ci_firewall_device_cisco" : set_cisco_firewall_dataframe,
    "cmdb_ci_firewall_device_palo_alto" : set_palo_firewall_dataframe,
    "cmdb_ci_ip_firewall" : set_ip_firewall_dataframe,
    "cmdb_ci_ip_router" : set_ip_firewall_dataframe,
    "cmdb_ci_ip_switch" : set_ip_switch_dataframe,
    "cmdb_ci_netgear" : set_netgear_dataframe,
    "cmdb_ci_wap_network" : set_wireless_ap_dataframe,
}

cisco_firewall_dataframe = pd.DataFrame()
palo_firewall_dataframe = pd.DataFrame()
ip_firewall_dataframe = pd.DataFrame()
ip_router_dataframe = pd.DataFrame()
ip_switch_dataframe = pd.DataFrame()
netgear_dataframe = pd.DataFrame()
wireless_ap_dataframe = pd.DataFrame()

def encrypt_data(str_encrypt):
    if str_encrypt == None or str_encrypt == "":
        return ""
    
    else:
        encrypted_string = data_key._encrypt_from_parts(bytes(str_encrypt),0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
        return encrypted_string

def decrypt_data(str_decrypt):
    decrypt_string = data_key.decrypt(str_decrypt).decode()

    return decrypt_string

def callback_thread(function, *args):
    asyncio.run(function(*args))

#FUNCTIONS
def apply_background_color(rows):
    if rows['operational_status'] == "Operational" \
        and rows['install_status'] == "Installed" \
        and int(rows['total_days']) <= 15:
        return ['background-color: green' for row in rows]
    
    elif rows['operational_status'] == "Operational" \
        and rows['install_status'] == "Installed" \
        and int(rows['total_days']) > 15:
        return ['background-color: orange' for row in rows]
    
    else:
        return ['background-color: red' for row in rows]
    
def align_center(rows):
    return ['text-align: center' for row in rows]

def write_to_excel(api_table_name, dataframe):
    file_name = f"Reports/{now_date}/Full_Report_{now_date}_Report.xlsx"

    with pd.ExcelWriter(file_name, mode='a', engine="openpyxl") as writer:
        dataframe.reset_index(drop=True)\
        .style.apply(align_center)\
        .apply(apply_background_color, axis=1)\
        .to_excel(writer, sheet_name=api_table_name, index=False)
        
def check_ping(ip_address):
    command = f"ping -n 1 {ip_address}"

    try:
        subprocess.check_output(command, shell=True)
        return True
    
    except subprocess.CalledProcessError as error:
        return False
    
def get_nslookup_forward(hostname):
    try:
        socket.gethostbyname(hostname)
        return 1
    
    except (socket.herror, socket.gaierror) as error:
        return 0
    
def get_nslookup_reverse(ip_address):
    try:
        socket.gethostbyaddr(ip_address)
        return 1
    
    except (socket.herror, socket.gaierror) as error:
        return 0

def write_to_text_legend():
    file_name = f"Reports/{now_date}/Full_Counts_{now_date}_Report"
    template = """Definitions
	High confidence:

	Operational = per MID server age of total days  < 15 days" and operational status = "Operational" and install status "Installed"
	Retired = per MID server age of total days > 16 days" operational status = "Retired" and install status "Retired"

	Low confidence:

	Untrusted Operational = per MID server age of total days > 16 days" operational status = "Operational\n\n"""
    
    with open(f'{file_name}.txt', 'a+') as f:
    	f.write(template)
    


def write_to_text_info(api_name, good_count, review_count, bad_count, software_installed, supported, location, managed_by, managed_by_group):
    total_count = good_count + bad_count + review_count

    file_name = f"Reports/{now_date}/Full_Counts_{now_date}_Report"

    def divide(x,y):
        try:
            return round(x/y, 2)
        except ZeroDivisionError:
            return 0

    template = f"""{api_name}

	Records in CMDB Discovery
		{total_count - review_count}/{total_count} - Total High Confidence
			{good_count}/{total_count} - ({divide(good_count, total_count) * 100}%) - Operational
			{bad_count}/{total_count} - ({divide(bad_count, total_count) * 100}%)- Retired

		{review_count}/{total_count} - Total Low Confidence
			{review_count}/{total_count} - ({divide(review_count, total_count) * 100}%) - Untrusted Operational

    High Confidence CI_Records Completeness	
		{software_installed}/{good_count} - ({divide(software_installed, good_count) * 100}%) - Software
		{supported}/{good_count} - ({divide(supported, good_count) * 100}%) - Supported By
		{location}/{good_count} - ({divide(location, good_count) * 100}%) - Location
		{managed_by}/{good_count} - ({divide(managed_by, good_count) * 100}%) - Managed By
		{managed_by_group}/{good_count} - ({divide(managed_by_group, good_count) * 100}%) - Managed By Group\n"""

    with open(f'{file_name}.txt', 'a+') as f:
        f.write(template)

def write_dictionary(data):
    for key, values in data.items():
        file_name = f"Reports/{now_date}/Software_{key}_{now_date}_Report"

        with open(f'{file_name}.txt', 'a+') as f:
            f.write(json.dumps(values, indent=4)\
                    .replace("{", "")\
                    .replace("}", "")
                    .replace("        ", "")\
                    .replace("\n", "")\
                    .replace("    ,", "\n")\
            )

def set_class_count_mapping(class_name):
    global class_count_mapping

    return class_count_mapping.update({class_name : 0})

def update_class_count_mapping(class_name):
    global class_count_mapping

    return class_count_mapping.update({class_name : (class_count_mapping.get(class_name) + 1)})

def get_class_count_mapping():
    return class_count_mapping

def set_field_count_mapping(class_name):
    global field_count_mapping

    return field_count_mapping.update({class_name : 0})

def update_field_count_mapping(class_name):
    global field_count_mapping

    return field_count_mapping.update({class_name : (field_count_mapping.get(class_name) + 1)})

def get_field_count_mapping():
    return field_count_mapping

def get_total_class_count_mapping(name):
    good, review, retired = 0, 0, 0

    for key, value in class_count_mapping.items():
        if key.startswith(name + "_good"):
            good = value
        elif key.startswith(name + "_needs_review"):
            review = value
        elif key.startswith(name + "_retired"):
            retired = value

    return good, review, retired

def get_total_field_count_mapping(name):
    software, supported, location, managed_by_team, managed_by_group = 0, 0, 0, 0, 0

    for key, value in field_count_mapping.items():
        if key.startswith(name + "_software"):
            software = value
        elif key.startswith(name + "_supported"):
            supported = value
        elif key.startswith(name + "_location"):
            location = value
        elif key.startswith(name + "_managed_by_team"):
            managed_by_team = value
        elif key.startswith(name + "_managed_by_group"):
            managed_by_group = value

    return software, supported, location, managed_by_team, managed_by_group

def set_software_mapping(class_name, software_primary_key):
    global software_mapping

    return software_mapping[class_name].append({software_primary_key : 1})

def update_software_mapping(class_name, software_primary_key, index):
    global software_mapping

    software_mapping[class_name][index] = {software_primary_key : software_mapping.get(class_name)[index].get(software_primary_key) + 1}

def get_software_mapping():
    return software_mapping

def write_to_sql(api_name, good, review, retired, software_installed, location, managed_by_group):
    cnxn, cursor = DC.new_database_connection()

    try:
        query_insert = "INSERT INTO snow_asset_count VALUES(?,?,?,?,?,?,?,?)"
        parameter = api_name, good, review, retired, software_installed, location, managed_by_group, now_date

        cursor.execute(query_insert, parameter)
        cnxn.commit()

    except Exception as e:
        print(f"Failed to insert data to SQL", "\n", e)

def make_folder():
    path = f"Reports/{now_date}"

    if not os.path.isdir(path):
        os.makedirs(path)

def create_workbook():
    #Create Workbook
    file_name = f"Reports/{now_date}/Full_Report_{now_date}_Report.xlsx"
    wb = Workbook()
    wb.save(file_name)