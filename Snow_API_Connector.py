import Database.DB_Connection as DC
from Snow_API_Initial_Data import *

computer_dataframe = pd.DataFrame()
window_dataframe = pd.DataFrame()
linux_dataframe = pd.DataFrame()
esx_dataframe = pd.DataFrame()
class_count_mapping = dict()
total_count_mapping = dict()
field_count_mapping = dict()
excel_list = ['cmdb_ci_computer', 'cmdb_ci_win_server', 'cmdb_ci_linux_server', 'cmdb_ci_esx_server']
software_list_linux = ['cmdb_ci_linux_server', 'cmdb_ci_unix_server', 'cmdb_ci_esx_server']
software_list_windows = ['cmdb_ci_win_server', 'cmdb_ci_computer']

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

    print(software, supported, location, managed_by_team, managed_by_group)

    return software, supported, location, managed_by_team, managed_by_group

def set_computer_dataframe(new_dataframe, data):
    global computer_dataframe

    computer_dataframe = pd.concat([new_dataframe, pd.DataFrame(pd.json_normalize(data))])
    sleep(.25)

def get_computer_dataframe():
    return computer_dataframe

def set_window_dataframe(new_dataframe, data):
    global window_dataframe

    window_dataframe = pd.concat([new_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_window_dataframe():
    return window_dataframe

def set_linux_dataframe(new_dataframe, data):
    global linux_dataframe

    linux_dataframe = pd.concat([new_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_linux_dataframe():
    return linux_dataframe

def set_esx_dataframe(new_dataframe, data):
    global esx_dataframe

    esx_dataframe = pd.concat([new_dataframe, pd.DataFrame(pd.json_normalize(data))])

def get_esx_dataframe():
    return esx_dataframe

def make_folder():
    path = f"Reports/{now_date}"

    if not os.path.isdir(path):
        os.makedirs(path)

    return path

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

#Subtract 2 dates
def days_between(d1, d2):
    d1 = datetime.strptime(d1, "%Y-%m-%d")
    d2 = datetime.strptime(d2, "%Y-%m-%d")
    return abs((d2 - d1).days)

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
        #NEED TO INSERT TO DATABASE
        #insert_to_database_data(cnxn, cursor)

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
    responses = vulnerability_entry.get()

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

async def get_api_asset(api_table_name, entry_offset, limit_count, thread_number):
    #Dict
    data = dict()
    software_full_list = dict()

    #Create client object
    client = pysnow.Client(instance=instance, user=username, password=password)

    #Session Thread Safe
    session_api = config.get('API', f"{api_table_name}")
    session = client.resource(api_path=session_api)

    session_software_api = config.get('API', "cmdb_sam_sw_install")
    session_software = client.resource(api_path=session_software_api)

    session_sys_user_api = config.get('API', "sys_user_group")
    session_sys_user = client.resource(api_path=session_sys_user_api)

    session_location_api = config.get('API', "cmn_location")
    session_location = client.resource(api_path=session_location_api)

    #Path Location
    path = make_folder()

    sleep(.2)

    file_name = f"Reports/{now_date}/Full_Report_{now_date}_Report.xlsx"
    wb = Workbook()
    wb.save(file_name)

    #Database
    cnxn, cursor = DC.new_database_connection()

    #Timer
    start = time()

    #Offset parameter from function arg to start record from api call
    offset_parameter = entry_offset
    limit_parameter = limit_count

    #Query Builder
    queryBuilder = pysnow.QueryBuilder().field('serial_number').is_not_empty()
    
    #FUNCTIONS
    def find_software_full():
        software_count = 0

        session_software.parameters.exclude_reference_link = True
        
        query_builder = pysnow.QueryBuilder()\
        .field('installed_on').equals(data['sys_id'])

        responses = session_software.get(query=query_builder)

        try:
            if good_record():
                for response in responses.all():
                    if response is not None:
                        if response['primary_key'] in software_full_list.keys():
                            software_count += 1
                            software_full_list.update({response['primary_key'] : software_full_list.get(response['primary_key']) + 1})

                        else:
                            software_count += 1
                            software_full_list.update({response['primary_key'] : 1})
        
        except pysnow.exceptions.NoResults:
            print(f"NO RESULT ERROR FROM {data['computer_name']}")
    
        return software_count
                
    
    def find_software(name, software_name = "", without_publisher=False):
            session_software.parameters.exclude_reference_link = True

            if without_publisher == False:
                query_builder = pysnow.QueryBuilder()\
                .field('publisher').contains(name)\
                .AND().field("display_name").contains(software_name)\
                .AND().field('installed_on').equals(data['sys_id'])

            else:
                query_builder = pysnow.QueryBuilder()\
                .field("display_name").contains(software_name)\
                .AND().field('installed_on').equals(data['sys_id'])    
            
            responses = session_software.get(query=query_builder, limit=1)

            try:
                for response in responses.all():
                    if response['publisher'] == name or software_name.lower() in response['display_name'].lower():
                        data[f'{name.lower()}_installed'] = 1

            except Exception as e:
                print(e)


    def write_file(file_name, data):
        with open(f'{file_name}.txt', 'a+') as f:
            f.write(data)

    def get_sys_owner(sys_id):
        responses = session_sys_user.get(query = {"sys_id": sys_id})

        for response in responses.all():
            return response['name']
        
    def get_location(sys_id):
        responses = session_location.get(query = {"sys_id": sys_id})

        for response in responses.all():
            return response['name']
        
    def good_record():
        return data['operational_status'] == "Operational" \
            and data['install_status'] == "Installed" \
            and int(data['total_days']) <= 15
    
    def bad_record():
        return data['operational_status'] == "Operational" \
        and data['install_status'] == "Installed" \
        and int(data['total_days']) > 15
    
    def retired_record():
        return data['operational_status'] == "Retired" \
        and data['install_status'] == "Retired" \
        or \
        data['operational_status'] == "Non-Operational"\
        and data['install_status'] == "Retired" \
            
    def initial_count_count_map():
        set_class_count_mapping(response['sys_class_name'] + "_good")
        set_class_count_mapping(response['sys_class_name'] + "_needs_review")
        set_class_count_mapping(response['sys_class_name'] + "_retired")

    def initial_field_count_map():
        set_field_count_mapping(response['sys_class_name'] + "_software")
        set_field_count_mapping(response['sys_class_name'] + "_supported")
        set_field_count_mapping(response['sys_class_name'] + "_location")
        set_field_count_mapping(response['sys_class_name'] + "_managed_by_team")
        set_field_count_mapping(response['sys_class_name'] + "_managed_by_group")

    def count_mapping_record_review():
        if good_record():
            return update_class_count_mapping(response['sys_class_name'] + "_good")
        elif bad_record():
            return update_class_count_mapping(response['sys_class_name'] + "_needs_review")
        else:
            return update_class_count_mapping(response['sys_class_name'] + "_retired")
        
    def field_mapping_record_review():
        if good_record() or retired_record():
            if data['software_count'] > 0:
                update_field_count_mapping(response['sys_class_name'] + "_software")
            
            if data['supported_by'] is not None and data['supported_by'] != "":
                update_field_count_mapping(response['sys_class_name'] + "_supported")
            
            if data['location'] is not None and data['location'] != "":
                update_field_count_mapping(response['sys_class_name'] + "_location")
            
            if data['managed_by'] is not None and data['managed_by'] != "":
                update_field_count_mapping(response['sys_class_name'] + "_managed_by_team")
            
            if data['managed_by_group'] is not None and data['managed_by_group'] != "":
                update_field_count_mapping(response['sys_class_name'] + "_managed_by_group")

    def compare_data(data, report_name, search):
        report_dataframe = pd.read_csv(report_name)

        #IF GOOD RECORD
        if good_record()\
            and data[search] == 0:

                #WRITE GOOD RECORDS NA SERVICENOW
                if search == "crowdstrike_installed":
                    write_file(f"{path}/SNOW_Only_{search}_{response['sys_class_name']}_{now_date}", f"{data['computer_name']} : {data['serial_number']}\n")

                #NOT IN SNOW AND NOT FOUND IN COMPARABLE DATA Crowdstrike
                if search == "crowdstrike_installed" and report_dataframe['Serial Number'].eq(data['serial_number']).sum() == 0:
                    write_file(f"{path}/SNOW_AND_CROWD_{search}_{response['sys_class_name']}_{now_date}", f"{data['computer_name']} : {data['serial_number']}\n")

                #WRITE GOOD RECORDS NA SERVICENOW
                if search == "datadog_installed":
                    write_file(f"{path}/SNOW_Only_{search}_{response['sys_class_name']}_{now_date}", f"{data['computer_name']} : {data['serial_number']}\n")

                #NOT IN SNOW AND NOT FOUND IN COMPARABLE DATA Datadog
                if search == "datadog_installed" and report_dataframe['server_name'].eq(data['computer_name']).sum() == 0:
                    write_file(f"{path}/SNOW_AND_DataDog_{search}_{response['sys_class_name']}_{now_date}", f"{data['computer_name']} : {data['serial_number']}\n")

    try:
        api_responses = session.get(query=queryBuilder, offset = offset_parameter, limit = limit_parameter)

        try:
            for response in api_responses.all():
                encrypt_computer_name = encrypt_data(response['name'].replace("formerly: ", "").lower().encode())
                encrypt_default_gateway = encrypt_data(response['default_gateway'].lower().encode())
                encrypt_ip = encrypt_data(response['ip_address'].lower().encode())

                data['computer_name'] = response['name']
                data['ip_address'] = response['ip_address']
                data['default_gateway'] = response['default_gateway']
                data['operational_status'] = operational_status_mapping.get(response['operational_status'])
                data['install_status'] = install_status_mapping.get(response['install_status'])
                data['server_operating_system'] = response['os']
                data['server_model_id'] = "" if response['model_id'] == "" else response['model_id']['value']
                data['mac_address'] = response['mac_address'].strip().replace(":","-")
                data['sys_id'] = response['sys_id']
                data['created_date'] = now_date
                data['api_table'] = api_table_name
                data['first_discovered'] = now_date if response['first_discovered'] == "" else response['first_discovered'].strip().split(" ")[0]
                data['last_discovered'] = data['first_discovered'] if response['last_discovered'] == "" else response['last_discovered'].strip().split(" ")[0]
                data['discovery_source'] = response['discovery_source']
                data['total_days'] = days_between(now_date, data['last_discovered'])
                data['serial_number'] = response['serial_number']
                data['supported_by'] = response['supported_by']
                data['managed_by'] = response['managed_by']
                data['managed_by_group'] = "" if response['managed_by_group'] == "" else get_sys_owner(response['managed_by_group']['value'])
                data['location'] = "" if response['location'] == "" else get_location(response['location']['value'])
                data['software_count'] = find_software_full()
                data['microsoft_configuration_client_installed'] = 0
                data['crowdstrike_installed'] = 0
                data['tenable_installed'] = 0
                data['datadog_installed'] = 0
                data['mcafee_installed'] = 0
                data['troubleshooting_tools_installed'] = 0

                #CHECK SOFTWARE FOR WINDOWS
                if response['sys_class_name'] in software_list_windows:
                    find_software("CrowdStrike", "Control")
                    find_software("Tenable", "Agent")
                    find_software("Datadog", "Agent")
                    find_software('McAfee', "Agent")
                    find_software("microsoft_configuration_client", "Configuration Manager Client", True)
                    find_software("troubleshooting_tools", "WinPcap", True)

                #CHECKS SOFTWARE FOR LINUX
                if response['sys_class_name'] in software_list_linux:
                    find_software("crowdstrike", "falcon-sensor", True)
                    find_software("tenable", "NessusAgent", True)
                    find_software("Datadog", "Agent")
                    
                #DIFFERENT DATAFRAME FOR EXCEL BASED ON CLASS NAME
                if response['sys_class_name'] == "cmdb_ci_computer":
                    set_computer_dataframe(computer_dataframe, data)

                elif response['sys_class_name'] == "cmdb_ci_win_server":
                    set_window_dataframe(window_dataframe, data)

                elif response['sys_class_name'] == "cmdb_ci_linux_server":
                    set_linux_dataframe(linux_dataframe, data)

                elif response['sys_class_name'] == "cmdb_ci_esx_server":
                    set_esx_dataframe(esx_dataframe, data)
                    
                #REVISES COUNTS BASED ON GOOD/BAD/RETIRED RECORDS
                if (response['sys_class_name'] + "_good") not in class_count_mapping.keys():
                    initial_count_count_map()
                    count_mapping_record_review()

                else:
                    count_mapping_record_review()

                if (response['sys_class_name'] + "_supported" not in field_count_mapping.keys()):
                    initial_field_count_map()
                    field_mapping_record_review()
                
                else:
                    field_mapping_record_review()

                #COMPARES Crowdstrike and DataDog reports for more accurate measures
                compare_data(data, "Crowdstrike_Reports/5649_hosts_2023-06-01T16_22_53Z.csv", "crowdstrike_installed")
                compare_data(data, "Datadog_Reports/2023-06-01_DataDog.csv", "datadog_installed")

                # try:
                #     query_insert = "INSERT INTO snow_cmdb_list VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                #     parameter = data['computer_name'], data['ip_address'], data['default_gateway'], data['operational_status'], data['server_operating_system'], data['server_model_id'], data['mac_address'], data['sys_id'], data['created_date'], data['api_table'], data['first_discovered'], data['last_discovered'], data['discovery_source'], data['total_days'], data['serial_number']

                #     cursor.execute(query_insert, parameter)
                #     cnxn.commit()

                # except Exception as e:
                #     print(f"Failed to insert data for {response}", "\n", e)

            write_file(f"{path}/Dictionary_{response['sys_class_name']}_{now_date}.txt", json.dumps(software_full_list, indent=4) + '\n')
            
        except Exception as e:
            print("Failed at loop response", "\n", e)
    
    except Exception as e:
        print("Failed to receive a 200 HTTP Request", "\n", e)

    end = time()
    print(f"Time Taken Entries for Thread {thread_number}: {int(end - start)} seconds")