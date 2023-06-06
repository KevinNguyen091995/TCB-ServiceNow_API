from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from datetime import datetime, timedelta
from UliPlot.XLSX import auto_adjust_xlsx_column_width
from time import time, sleep
from openpyxl import Workbook, load_workbook
from collections import OrderedDict
import subprocess
import socket
import configparser
import pandas as pd
import asyncio
import csv
import threading
import os
import json
import math

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
class_count_mapping = dict()
field_count_mapping = dict()
total_count_mapping = dict()
software_mapping = dict({
    "cmdb_ci_computer" : [],
    "cmdb_ci_win_server" : [],
})

#Initial Arrays API List
excel_list = ['cmdb_ci_computer', 'cmdb_ci_win_server', 'cmdb_ci_linux_server', 'cmdb_ci_esx_server']
software_list_linux = ['cmdb_ci_linux_server', 'cmdb_ci_unix_server', 'cmdb_ci_esx_server']
software_list_windows = ['cmdb_ci_win_server', 'cmdb_ci_computer']

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
        
def check_ping(hostname):
    try:
        subprocess.check_output(['ping', hostname])
        return True
    
    except subprocess.CalledProcessError as error:
        return False
    
def get_nslookup_forward(hostname):
    try:
        socket.gethostbyname(hostname)
        return 1
    
    except (socket.herror, socket.gaierror):
        return 0
    
def get_nslookup_reverse(ip_address):
    try:
        socket.gethostbyaddr(ip_address)
        return 1
    
    except (socket.herror, socket.gaierror):
        return 0

def write_to_text(api_name, good_count, review_count, bad_count, software_installed, supported, location, managed_by, managed_by_group):
    total_count = good_count + bad_count + review_count

    file_name = f"Reports/{now_date}/Full_Counts_{now_date}_Report.txt"

    def divide(x,y):
        try:
            return round(x/y, 2)
        except ZeroDivisionError:
            return 0

    template = f"""{api_name}

    Records in CMDB Discovery
    	{total_count - review_count}/{total_count} - Total High Confidence
        	{good_count}/{total_count} - ({divide(good_count, total_count) * 100}%) Count of high confidence asset ci_record "operational" per MID server age of total days "<15 days" and operational status = "Operational" and install status "Installed"
            {bad_count}/{total_count} - ({divide(bad_count, total_count) * 100}%)- Count of high confidence asset ci_record "retired" per MID server age of total days">16 days" operational status = "Retired" and install status "Retired"

        {review_count}/{total_count} - Total Low Confidence
        	{review_count}/{total_count} - ({divide(review_count, total_count) * 100}%) - Count of low confidence asset ci_record "retired" per MID server age of total days">16 days" operational status = "Operational"

    High Confidence CI_Records Completeness	
		{software_installed}/{total_count} - ({divide(software_installed, total_count) * 100}%) - Count of high confidence asset ci_record "operational" with "Software" field populated.
		{supported}/{total_count} - ({divide(supported, total_count) * 100}%) - Count of high confidence asset ci_record "operational" with "Supported by" field populated.
		{location}/{total_count} - ({divide(location, total_count) * 100}%) - Count of high confidence asset ci_record "operational" with "Location" field populated.
		{managed_by}/{total_count} - ({divide(managed_by, total_count) * 100}%) - Count of high confidence asset ci_record "operational" with "Managed by" field populated.
		{managed_by_group}/{total_count} - ({divide(managed_by_group, total_count) * 100}%) - Count of high confidence asset ci_record "operational" with "Managed by group" field populated.\n
    """

    with open(f'{file_name}.txt', 'a+') as f:
        f.write(template)

def write_dictionary(data):
    file_name = f"Reports/{now_date}/Full_Software_{now_date}_Report.txt"

    with open(f'{file_name}.txt', 'a+') as f:
        f.write(json.dumps(data, indent=4))


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

def make_folder():
    path = f"Reports/{now_date}"

    if not os.path.isdir(path):
        os.makedirs(path)

    return path