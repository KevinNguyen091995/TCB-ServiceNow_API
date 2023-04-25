import Database.DB_Connection as DC
from Key_Functions_Modules import *
import pysnow
import math

#Data
data = dict()
software = dict()
owners = []
vul_entry_dict = dict()
vul_active_count = dict()
vul_inactive_count = dict()

# Create client object
c = pysnow.Client(instance=instance, user=username, password=password)

#API
sys_user_api = config.get('API', 'sys_user')
incident_api = config.get('API', 'incident')
software_api = config.get('API', 'software_install')
vulnerability_ci_api = config.get('API', 'vulnerability_ci')
vulnerability_item_api = config.get('API', 'vulnerability_item') 
vulnerability_entry_api = config.get('API', 'vulnerability_entry')
sys_object_api = config.get('API', 'sys_object')
sys_user_group_api = config.get('API', 'sys_user_group')
cmdb_ci_server_api = config.get("API", 'cmdb_ci_server')
cmdb_ci_computer_api = config.get("API", "cmdb_ci_computer")

# Define a resource, here we'll use the incident table API
sys_user = c.resource(api_path=sys_user_api)
incident = c.resource(api_path=incident_api)
software_install = c.resource(api_path=software_api)
vulnerability_ci = c.resource(api_path=vulnerability_ci_api)
sys_object = c.resource(api_path=sys_object_api)
vulnerability_item = c.resource(api_path=vulnerability_item_api)
vulnerability_entry = c.resource(api_path=vulnerability_entry_api)
sys_user_group = c.resource(api_path=sys_user_group_api)
cmdb_ci_server_list = c.resource(api_path=cmdb_ci_server_api)
cmdb_ci_computer = c.resource(api_path=cmdb_ci_computer_api)

"""
Function to run API calls for a certain vul and grabs data of owner of vul
"""
#Service now Vulnerabilities
def get_service_now_vul():
    cnxn, cursor = DC.new_database_connection()

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
        insert_to_database_data(cnxn, cursor)

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
    responses = vulnerability_entry.get(limit = 700)

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
    cnxn, cursor = DC.new_database_connection()
    global index_set

    start = time()

    #Offset parameter from function arg to start record from api call
    offset_parameter = math.floor(entry_offset)

    #Limits the parameter of the offset so get data from offset 0 to last record
    limit_parameter = math.ceil(offset_parameter + (len(vul_entry_dict) / total_threads))
    
    #Do not add dupe data based on index since entries are split with float # and casting back to int
    index_set = set()

    for index, (key, value) in enumerate(vul_entry_dict.items()):
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
            cursor.execute(query, parameter)
            cnxn.commit()
    
    end = time()
    print(f"Time Taken Entries for Thread {thread_number}: {int(end - start)} seconds")

async def get_cmdb_server(entry_offset, thread_number):
    cnxn, cursor = DC.new_database_connection()
    start = time()

    #Offset parameter from function arg to start record from api call
    offset_parameter = math.floor(entry_offset)

    #Limits the parameter of the offset so get data from offset 0 to last record
    limit_parameter = math.ceil(offset_parameter + 1000)

    operational_status_mapping = {
        '1' : 'Operational',
        '2' : 'Non-Operational',
        '6' : 'Retired'
    }

    queryBuilder = pysnow.QueryBuilder().field('ip_address').is_not_empty().AND().field('ip_address').not_equals('0.0.0.0')

    try:
        cmdb_server_response = cmdb_ci_server_list.get(query=queryBuilder, offset = offset_parameter, limit = limit_parameter)

        try:
            for response in cmdb_server_response.all():
                encrypt_server_name = data_key.encrypt(bytes(response['name'].replace("formerly: ", "").lower().encode()))
                encrypt_default_gateway = encrypt_data(response['default_gateway'].lower().encode())
                encrypt_ip = data_key.encrypt(bytes(response['ip_address'].lower().encode()))

                data['computer_name'] = encrypt_server_name
                data['ip_address'] = encrypt_ip
                data['default_gateway'] = encrypt_default_gateway
                data['operational_status'] = operational_status_mapping.get(response['operational_status'])
                data['server_operating_system'] = response['os']
                data['server_model_id'] = "" if response['model_id'] == "" else response['model_id']['value']
                data['mac_address'] = response['mac_address']
                data['sys_id'] = response['sys_id']
                data['created_date'] = now_date
                data['api_table'] = cmdb_ci_computer_api


                try:
                    query_insert = "INSERT INTO test_snow_cmdb_list VALUES(?,?,?,?,?,?,?,?,?,?)"
                    parameter = data['computer_name'], data['ip_address'], data['default_gateway'], data['operational_status'], data['server_operating_system'], data['server_model_id'], data['mac_address'], data['sys_id'], data['created_date'], data['api_table']

                    cursor.execute(query_insert, parameter)
                    cnxn.commit()

                except Exception as e:
                    print(f"Failed to insert data for {response}", "\n", e)

        except Exception as e:
            print("Failed at loop response", "\n", e)
    
    except Exception as e:
        print("Failed to receive a 200 HTTP Request", "\n", e)

    end = time()
    print(f"Time Taken Entries for Thread {thread_number}: {int(end - start)} seconds")

async def get_cmdb_computer(entry_offset, thread_number):
    cnxn, cursor = DC.new_database_connection()
    start = time()

    #Offset parameter from function arg to start record from api call
    offset_parameter = math.floor(entry_offset)

    #Limits the parameter of the offset so get data from offset 0 to last record
    limit_parameter = math.ceil(offset_parameter + 2000)

    operational_status_mapping = {
        '1' : 'Operational',
        '2' : 'Non-Operational',
        '6' : 'Retired'
    }

    queryBuilder = pysnow.QueryBuilder().field('ip_address').is_not_empty()

    try:
        cmdb_computer_response = cmdb_ci_computer.get(query=queryBuilder, offset = offset_parameter, limit = limit_parameter)

        try:
            for response in cmdb_computer_response.all():
                encrypt_computer_name = encrypt_data(response['name'].replace("formerly: ", "").lower().encode())
                encrypt_default_gateway = encrypt_data(response['default_gateway'].lower().encode())
                encrypt_ip = encrypt_data(response['ip_address'].lower().encode())

                data['computer_name'] = encrypt_computer_name
                data['ip_address'] = encrypt_ip
                data['default_gateway'] = encrypt_default_gateway
                data['operational_status'] = operational_status_mapping.get(response['operational_status'])
                data['server_operating_system'] = response['os']
                data['server_model_id'] = "" if response['model_id'] == "" else response['model_id']['value']
                data['mac_address'] = response['mac_address']
                data['sys_id'] = response['sys_id']
                data['created_date'] = now_date
                data['api_table'] = cmdb_ci_computer_api


                try:
                    query_insert = "INSERT INTO test_snow_cmdb_list VALUES(?,?,?,?,?,?,?,?,?,?)"
                    parameter = data['computer_name'], data['ip_address'], data['default_gateway'], data['operational_status'], data['server_operating_system'], data['server_model_id'], data['mac_address'], data['sys_id'], data['created_date'], data['api_table']

                    cursor.execute(query_insert, parameter)
                    cnxn.commit()

                except Exception as e:
                    print(f"Failed to insert data for {response}", "\n", e)

        except Exception as e:
            print("Failed at loop response", "\n", e)
    
    except Exception as e:
        print("Failed to receive a 200 HTTP Request", "\n", e)

    end = time()
    print(f"Time Taken Entries for Thread {thread_number}: {int(end - start)} seconds")


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

def cmdb_distinct():
    cnxn, cursor = DC.new_database_connection()

    try:
        cursor.execute(f"INSERT INTO snow_cmdb_list SELECT DISTINCT * FROM test_snow_cmdb_list")
        cnxn.commit()
    
    except Exception as e:
        print(f"Failed To DISTINCT Data", "\n", e)