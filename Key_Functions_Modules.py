from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from datetime import datetime, timedelta
from time import time
import configparser
import pandas as pd
import csv
import threading
import asyncio


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