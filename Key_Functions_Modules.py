from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from datetime import datetime, timedelta
from UliPlot.XLSX import auto_adjust_xlsx_column_width
from time import time, sleep
from openpyxl import Workbook, load_workbook
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

#Datakey
data_key = Fernet(key)

#DateTime
now_date = datetime.now().strftime("%Y-%m-%d")

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
    
    else:
        return ['background-color: red' for row in rows]
    
def align_center(rows):
    return ['text-align: center' for row in rows]

def write_to_excel(api_table_name, dataframe):
    file_name = f"Reports/{now_date}/{api_table_name}_{now_date}_Report.xlsx"

    with pd.ExcelWriter(file_name, mode='w', engine="openpyxl") as writer:
        dataframe.reset_index(drop=True)\
        .style.apply(align_center)\
        .apply(apply_background_color, axis=1)\
        .to_excel(writer, sheet_name=f"Asset Report", index=False)

        auto_adjust_xlsx_column_width(dataframe, writer, sheet_name="Asset Report", margin=0)