import pysnow
import json
import configparser
import threading
import asyncio
import Database.DB_Connection as DC
from cryptography.fernet import Fernet
from datetime import datetime
from time import time

#ConfigParser Setup
config = configparser.ConfigParser()
config.read('config_snow.txt')

#DEFAULT
username = config.get('DEFAULT', 'username')
password = config.get('DEFAULT', 'password')
key = config.get('DEFAULT', 'key')
instance_dev = config.get('DEFAULT', 'instance_dev')
instance_test = config.get('DEFAULT', 'instance_test')
instance = config.get('DEFAULT', 'instance')
user_list = config.get('USER', 'users').split(",")

#Data
data = dict()
software = dict()
owners = []
vul_entry_dict = dict()
vul_active_count = dict()
vul_inactive_count = dict()
now_date = datetime.now().strftime("%Y-%m-%d")
data_key = Fernet(key)

# Create client object
c = pysnow.Client(instance=instance, user=username, password=password)

#API
personal_device_api = config.get('API', 'cmdb_ci_computer')
sys_user_api = config.get('API', 'sys_user')
incident_api = config.get('API', 'incident')
software_api = config.get('API', 'software_install')
vulnerability_ci_api = config.get('API', 'vulnerability_ci')
vulnerability_item_api = config.get('API', 'vulnerability_item') 
vulnerability_entry_api = config.get('API', 'vulnerability_entry')
sys_object_api = config.get('API', 'sys_object')
sys_user_group_api = config.get('API', 'sys_user_group')
cmdb_ci_server_api = config.get("API", 'cmdb_ci_server')

# Define a resource, here we'll use the incident table API
personal_device = c.resource(api_path=personal_device_api)
sys_user = c.resource(api_path=sys_user_api)
incident = c.resource(api_path=incident_api)
software_install = c.resource(api_path=software_api)
vulnerability_ci = c.resource(api_path=vulnerability_ci_api)
sys_object = c.resource(api_path=sys_object_api)
vulnerability_item = c.resource(api_path=vulnerability_item_api)
vulnerability_entry = c.resource(api_path=vulnerability_entry_api)
sys_user_group = c.resource(api_path=sys_user_group_api)
cmdb_ci_server_list = c.resource(api_path=cmdb_ci_server_api)

"""
Function to run API calls for a certain vul and grabs data of owner of vul
"""
#Service now Vulnerabilities
def get_service_now_vul():
    #Intitial Data
    global data
    vulnerability_scan = '2c1c80fb97a81d105cbeb4221153af5b'

    #PySnow Query for SSL Self Signed Certs
    responses  = vulnerability_item.get(query={"vulnerability" : vulnerability_scan })

    #API Response
    for vul_data in responses.all():
        data = {
            'dns' : vul_data['dns'].strip(),
            'number' : vul_data['number'].strip(),
            'active' : vul_data['active'].strip(),
            'ip_address' : vul_data['ip_address'].strip(),
            'port' : vul_data['port'].strip(),
            'description' : vul_data['description'].split(":")[0].replace("\n", " ").strip(),
            'risk_score' : vul_data['risk_score'].strip(),
            'first_found' : vul_data['first_found'].strip(),
            'last_state_changed_on' : vul_data['last_state_changed_on'].strip(),
            'assignment_group' : vul_data['assignment_group']['value'].strip(),
            'netbios' : vul_data['netbios'].strip(),
            'business_criticality' : vul_data['business_criticality'].strip(),
            'resolution_reason' : vul_data['resolution_reason'].replace("\n", " ").replace("\r", "").strip(),
            'protocol' : vul_data['protocol'].strip(),
            'vulnerability' : vulnerability_scan,
            'date_published' : "".strip(),
            'ten_vul_name' : "".strip(),
            "ten_solution" : "".strip(),
            'ten_id_name' : "".strip(),
            "owner_1_name" : "".strip(),
            'owner_1_email' : "".strip(),
            "owner_2_name" : "".strip(),
            'owner_2_email' : "".strip(),
        }

        check_owners(sys_user, "sys_id")
        get_data_equals(vulnerability_entry, "sys_id", vulnerability_scan)
        insert_to_database_data()

"""
Function to grab all vul_entry_item with key/value pairs. 
Used later to run a loop on all dictionary keys and call serviceNow API related to those vulnerability.
"""
def get_entry_count_vulnerability():
    start = time()
    #Global Data
    global vul_entry_dict
    global vul_active_count
    global vul_inactive_count

    #ServiveNow Response to call API
    responses = vulnerability_entry.get(limit = 45)

    #Reading all response data from API
    for response in responses.all():
        vul_entry_dict.update({response['sys_id'] : response['name']})
        vul_active_count.update({response['sys_id'] : 0})
        vul_inactive_count.update({response['sys_id'] : 0})

    end = time()
    print(f"Entries : {len(vul_entry_dict)}")
    print(f"Time Taken Entries : {int(end - start)} seconds")

#ASYNC Function to get vulnerability counts with multi-threading
async def get_count_vulnerability(entry_offset, thread_number, total_threads):
    global index_set

    start = time()

    #Offset parameter from function arg to start record from api call
    offset_parameter = int(entry_offset)

    #Limits the parameter of the offset so get data from offset 0 to last record
    limit_parameter = int(offset_parameter + (len(vul_entry_dict) / total_threads))
    
    #Do not add dupe data based on index since entries are split with float # and casting back to int
    index_set = set()

    for index, (key, value) in enumerate(vul_entry_dict.keys()):
        if index <= limit_parameter and index >= offset_parameter and index not in index_set:
            responses = vulnerability_item.get(query={'vulnerability' : key}, offset = offset_parameter, limit = limit_parameter)
        
            for response in responses.all():
                if response['active'] == 'true' and index not in index_set:
                    vul_active_count[key] = vul_active_count.get(key) + 1
                    index_set.add(index)

                if response['active'] == 'false' and index not in index_set:
                    vul_inactive_count[key] = vul_inactive_count.get(key) + 1
                    index_set.add(index)

        if vul_inactive_count.get(key) != 0 or vul_active_count.get(key) != 0:
            query = f"INSERT INTO snow_vulnerability_count VALUES (?, ?, ?, ?, ?)"
            parameter = key, value, vul_active_count.get(key), vul_inactive_count.get(key), now_date
            DC.cursor.execute(query, parameter)
            DC.cnxn.commit()
    
    end = time()
    print(f"Time Taken Entries for Thread {thread_number}: {int(end - start)} seconds")

def callback_thread(function, *args):
    asyncio.run(function(*args))

def get_count_vulnerability_thread_call():
    get_entry_count_vulnerability()

    get_count_thread_1 = threading.Thread(target=callback_thread, args=(get_count_vulnerability, (len(vul_entry_dict) / 4) * 0, 1, 4))
    get_count_thread_2 = threading.Thread(target=callback_thread, args=(get_count_vulnerability, (len(vul_entry_dict) / 4) * 1, 2, 4))
    get_count_thread_3 = threading.Thread(target=callback_thread, args=(get_count_vulnerability, (len(vul_entry_dict) / 4) * 2, 3, 4))
    get_count_thread_4 = threading.Thread(target=callback_thread, args=(get_count_vulnerability, (len(vul_entry_dict) / 4) * 3, 4, 4))

    get_count_thread_1.start()
    get_count_thread_2.start()
    get_count_thread_3.start()
    get_count_thread_4.start()


def insert_to_database_data():
        query = f"INSERT INTO {DC.table_name} VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        parameters = data['number'],data['ip_address'],data['dns'],data['port'],data['protocol'],data['netbios'],data['vulnerability'],data['ten_vul_name'],data['ten_solution'],data['ten_id_name'], data['first_found'], data['last_state_changed_on'],data['risk_score'], data['description'], data['owner_1_name'], data['owner_1_email'], data['owner_2_name'], data['owner_2_email'], data['business_criticality'], data['resolution_reason'], data['active']

        DC.cursor.execute(query, parameters)
        DC.cnxn.commit()

def check_owners(api, query_builder_field):
    get_data_equals(sys_user_group, "sys_id", data['assignment_group'])
    count = 1

    for owner in owners:
        responses = api.get(query = {query_builder_field: owner})

        for user_data in responses.all():
            data[f"owner_{count}_name"] = user_data['name']
            data[f'owner_{count}_email'] = user_data['email']
            count += 1

    return data

def get_cmdb_server():
    operational_status_mapping = {
        '1' : 'Operational',
        '2' : 'Non-Operational',
        '6' : 'Retired'
    }

    queryBuilder = pysnow.QueryBuilder().field('ip_address').is_not_empty().AND().field('ip_address').not_equals('0.0.0.0')

    responses = cmdb_ci_server_list.get(query=queryBuilder)

    for response in responses.all():
        encrypt_server_name = data_key.encrypt(bytes(response['name'].replace("formerly: ", "").encode()))
        encrypt_ip = data_key.encrypt(bytes(response['ip_address'].encode()))

        #DECODE USING
        #data_key.decrypt(encrypt_server_name).decode().replace("formerly: ", "")
        #data_key.decrypt(encrypt_ip).decode().replace("formerly: ", "")

        data['server_name'] = encrypt_server_name
        data['ip_address'] = encrypt_ip
        data['server_operating_system'] = response['os']
        data['operational_status'] = operational_status_mapping.get(response['operational_status']).replace("formerly: ", "")
        data['server_model_id'] = "" if response['model_id'] == "" else response['model_id']['value']

        DC.cursor.execute(f"INSERT INTO snow_server_list VALUES(?,?,?,?,?)", data['server_name'], data['ip_address'], data['server_operating_system'], data['operational_status'], data['server_model_id'])
        DC.cnxn.commit()

def get_data_equals(api, query_builder_field = "", query_builder_search = ""):
    global data
    global owners

    responses = api.get(query= {query_builder_field: query_builder_search})

    if api == sys_user_group:
        for sys_user_group_data in responses.all():
            owners = []
            try:
                owners.append(sys_user_group_data['u_l3_leader']['link'].split("/")[-1])
            except:
                pass

            try:
                owners.append(sys_user_group_data['u_l4_leader']['link'].split("/")[-1])
            except:
                pass

    if api == vulnerability_entry:
        for vul_entry_data in responses.all():
            data['ten_vul_name'] = vul_entry_data["name"]
            data["ten_solution"] = vul_entry_data['solution']
            data['ten_id_name'] = vul_entry_data['id']
            data['date_published'] = vul_entry_data['date_published']

    return data, software, owners