import pysnow
import json
import configparser
import threading
import asyncio
import Database.DB_Connection as DC
from datetime import datetime
from time import time

#Data
data = dict()
software = dict()
owners = []
vul_entry_dict = dict()
vul_active_count = dict()
vul_inactive_count = dict()
now_date = datetime.now().strftime("%Y-%m-%d")

#ConfigParser Setup
config = configparser.ConfigParser()
config.read('config_snow.txt')

#DEFAULT
username = config.get('DEFAULT', 'username')
password = config.get('DEFAULT', 'password')
instance_dev = config.get('DEFAULT', 'instance_dev')
instance_test = config.get('DEFAULT', 'instance_test')
instance = config.get('DEFAULT', 'instance')
user_list = config.get('USER', 'users').split(",")

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
    responses = vulnerability_entry.get(limit = 800)

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
    start = time()

    #Offset parameter from function arg to start record from api call
    offset_parameter = int(entry_offset)

    #Limits the parameter of the offset so get data from offset 0 to last record
    limit_parameter = int(offset_parameter + (len(vul_entry_dict) / total_threads))
    
    #Do not add dupe data based on index since entries are split with float # and casting back to int
    index_set = set()

    for index, (key) in enumerate(vul_entry_dict.keys()):
        if index <= limit_parameter and index >= offset_parameter and index not in index_set:
            responses = vulnerability_item.get(query={'vulnerability' : key}, offset = offset_parameter, limit = limit_parameter)
        
            for response in responses.all():
                if response['active'] == 'true' and index not in index_set:
                    vul_active_count[key] = vul_active_count.get(key) + 1
                    print(f"{thread_number} : {index}")
                    index_set.add(index)

                if response['active'] == 'false' and index not in index_set:
                    vul_inactive_count[key] = vul_inactive_count.get(key) + 1
                    print(f"{thread_number} : {index}")
                    index_set.add(index)

        # if vul_inactive_count.get(key) != 0 or vul_active_count.get(key) != 0:
        #     query = f"INSERT INTO snow_vulnerability_count VALUES (?, ?, ?, ?, ?)"
        #     parameter = key, value, vul_active_count.get(key), vul_inactive_count.get(key), now_date
        #     DC.cursor.execute(query, parameter)
        #     DC.cnxn.commit()
    
    end = time()
    print(f"Time Taken Entries for Thread {thread_number}: {int(end - start)} seconds")

def get_count_vulnerability_thread(*args):
    asyncio.run(get_count_vulnerability(*args))

def get_count_vulnerability_thread_call():
    get_entry_count_vulnerability()

    get_count_thread_1 = threading.Thread(target=get_count_vulnerability_thread, args=((len(vul_entry_dict) / 4) * 0, 1, 4))
    get_count_thread_2 = threading.Thread(target=get_count_vulnerability_thread, args=((len(vul_entry_dict) / 4) * 1, 2, 4))
    get_count_thread_3 = threading.Thread(target=get_count_vulnerability_thread, args=((len(vul_entry_dict) / 4) * 2, 3, 4))
    get_count_thread_4 = threading.Thread(target=get_count_vulnerability_thread, args=((len(vul_entry_dict) / 4) * 3, 4, 4))

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

def get_data_equals(api, query_builder_field = "", query_builder_search = ""):
    global data
    global software_data
    global owners

    responses = api.get(query= {query_builder_field: query_builder_search})

    if api == sys_user:
        for user_data in responses.all():
            data['name'] = user_data['name']
            data['user_name'] = user_data['user_name']
            data['sys_user_id'] = user_data['sys_id']
            data['email'] = user_data['email']
            data['last_login_time'] = user_data['last_login_time']

    if api == personal_device:
        for device_data in responses.all():
            data['sys_id'] = device_data['sys_id']
            data['personal_device_name'] = device_data['name']
            data['fqdn'] = device_data['fqdn']
            data['ip_address'] = device_data['ip_address']
            data['default_gate'] = device_data['default_gateway']
            data['os_version'] = device_data['os_version']
            data['last_login_id'] = device_data['u_last_logged_on_id']

    if api == software_install:
        software['name'] = data['name']
        software['username'] = data['user_name']
        software['personal_device_name'] = data['personal_device_name']
        software["software_list"] = list()

        for software_data in responses.all():
            software["software_list"].append({
            'software_name': software_data['display_name'],
            'publisher' : software_data['normalized_publisher'],
            'version' : software_data['normalized_version'],
            'install_date' : software_data['install_date'],
            'last_scanned' : software_data['last_scanned'],
            'active' : software_data['active']
            })

    if api == vulnerability_ci:
        for x in responses.all():
            print(x)

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