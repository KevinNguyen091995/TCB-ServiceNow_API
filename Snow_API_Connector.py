from Key_Functions_Modules import *

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

def set_data_initial(response, api_table_name):
    data = dict()
    global operational_status_mapping
    global install_status_mapping

    data['computer_name'] = response['name']
    data['ip_address'] = response['ip_address']
    data['operational_status'] = operational_status_mapping.get(response['operational_status'])
    data['install_status'] = install_status_mapping.get(response['install_status'])
    data['mac_address'] = response['mac_address'].strip().replace(":","-")
    data['sys_id'] = response['sys_id']
    data['created_date'] = now_date
    data['api_table'] = api_table_name
    data['serial_number'] = response['serial_number']
    data['server_model_id'] = "" if response['model_id'] == "" else response['model_id']['value']
    data['supported_by'] = response['supported_by']
    data['managed_by'] = response['managed_by']
    data['first_discovered'] = now_date if response['first_discovered'] == "" else response['first_discovered'].strip().split(" ")[0]
    data['last_discovered'] = data['first_discovered'] if response['last_discovered'] == "" else response['last_discovered'].strip().split(" ")[0]
    data['discovery_source'] = response['discovery_source']
    data['total_days'] = days_between(now_date, data['last_discovered'])
    data['microsoft_configuration_client_installed'] = 0
    data['crowdstrike_installed'] = 0
    data['tenable_installed'] = 0
    data['datadog_installed'] = 0
    data['mcafee_installed'] = 0
    data['troubleshooting_tools_installed'] = 0
    # data['pingable'] = 0
    # data['forward_dns'] = 0
    # data['reverse_dns'] = 0

    if api_table_name == "cmdb_ci_vm_instance":
        data['vm_inst_id'] = response['vm_inst_id']
        data['object_id'] = response['object_id']
        data['state'] = response['state']

    elif api_table_name == "cmdb_ci_computer":
        encrypt_computer_name = encrypt_data(response['name'].replace("formerly: ", "").lower().encode())
        encrypt_default_gateway = encrypt_data(response['default_gateway'].lower().encode())
        encrypt_ip = encrypt_data(response['ip_address'].lower().encode())
        data['default_gateway'] = response['default_gateway']
        data['server_operating_system'] = response['os']

    else:
        encrypt_computer_name = encrypt_data(response['name'].replace("formerly: ", "").lower().encode())
        encrypt_default_gateway = encrypt_data(response['default_gateway'].lower().encode())
        encrypt_ip = encrypt_data(response['ip_address'].lower().encode())
        data['default_gateway'] = response['default_gateway']

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

#GET API ASSET FUNCTION
async def get_api_asset(api_table_name, entry_offset, limit_count, thread_number, thread_lock):
    #FUNCTIONS
    def find_software_full(sys_class_name):
        software_count = 0

        session_software.parameters.exclude_reference_link = True
        
        query_builder = pysnow.QueryBuilder()\
        .field('installed_on').equals(data['sys_id'])

        responses = session_software.get(query=query_builder)

        try:
            if good_record() or bad_record():
                for response in responses.all():
                    if sys_class_name in software_mapping.keys() and thread_lock.locked != True:
                        for index, key in enumerate(software_mapping[sys_class_name]):
                            if response['primary_key'] in key:
                                thread_lock.acquire()
                                software_count += 1
                                update_software_mapping(sys_class_name, response['primary_key'], index)
                                thread_lock.release()
                                break

                        else:
                            thread_lock.acquire()
                            software_count += 1
                            set_software_mapping(sys_class_name, response['primary_key'])
                            thread_lock.release()

                    elif sys_class_name not in software_mapping.keys() and thread_lock.locked != True:
                        thread_lock.acquire()
                        software_mapping.update({sys_class_name : []})
                        thread_lock.release()
                    
        
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
        if good_record():
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

    def compare_data(data, report_name, search, criteria=False):
        report_dataframe = pd.read_csv(report_name)

        #IF GOOD RECORD
        if good_record() and\
            data[search] == 0:
                
                #WRITE GOOD RECORDS NA SERVICENOW
                if search == "crowdstrike_installed" and criteria == True:
                    write_file(f"{path}/SNOW_Only_{search}_{response['sys_class_name']}_{now_date}", f"{data['computer_name']} : {data['serial_number']} : {data['managed_by_group']}\n")

                #NOT IN SNOW AND NOT FOUND IN COMPARABLE DATA Crowdstrike
                if search == "crowdstrike_installed" and \
                (report_dataframe['Serial Number'].eq(data['serial_number']).sum() == 0 and \
                report_dataframe['Hostname'].eq(data['computer_name']).sum() == 0):
                    write_file(f"{path}/SNOW_AND_CROWD_{search}_{response['sys_class_name']}_{now_date}", f"{data['computer_name']} : {data['serial_number']} : {data['managed_by_group']}\n")

                #WRITE GOOD RECORDS NA SERVICENOW
                if search == "datadog_installed":
                    write_file(f"{path}/SNOW_Only_{search}_{response['sys_class_name']}_{now_date}", f"{data['computer_name']} : {data['serial_number']} : {data['managed_by_group']}\n")

                #NOT IN SNOW AND NOT FOUND IN COMPARABLE DATA Datadog
                if search == "datadog_installed" and \
                report_dataframe['server_name'].eq(data['computer_name']).sum() == 0:
                    write_file(f"{path}/SNOW_AND_DataDog_{search}_{response['sys_class_name']}_{now_date}", f"{data['computer_name']} : {data['serial_number']} : {data['managed_by_group']}\n")

    #Dict
    data = dict()

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

    #Timer
    start = time()

    #Offset parameter from function arg to start record from api call
    offset_parameter = entry_offset
    limit_parameter = limit_count

    #Query Builder
    queryBuilder = pysnow.QueryBuilder().field('serial_number').is_not_empty().AND().field("name").not_contains("AVD")
    
    try:
        if api_table_name in software_list_linux\
        or api_table_name in software_list_windows:
            api_responses = session.get(query=queryBuilder, offset = offset_parameter, limit = limit_parameter)
            
        else:
            api_responses = session.get(offset = offset_parameter, limit = limit_parameter)

        try:
            for response in api_responses.all():
                data = set_data_initial(response, api_table_name)
                data['software_count'] = find_software_full(response['sys_class_name'])
                data['managed_by_group'] = "" if response['managed_by_group'] == "" else get_sys_owner(response['managed_by_group']['value'])
                data['location'] = "" if response['location'] == "" else get_location(response['location']['value'])

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
                
                #CHECK NSLOOKUP
                # if(len(data['ip_address']) > 6 and ( good_record() or bad_record() )):
                #     data['forward_dns'] = get_nslookup_forward(data['computer_name'])
                #     data['reverse_dns'] = get_nslookup_reverse(data['ip_address'])
                #     data['pingable'] = 0 if check_ping(data['ip_address']) == False else 1

                if thread_lock.locked != True and response['sys_class_name'] in cmdb_mapping.keys():
                    thread_lock.acquire()
                    cmdb_mapping.get(response['sys_class_name'])(data)
                    thread_lock.release()
                    
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
                if response['sys_class_name'] in compare_list:
                    compare_data(data, "Crowdstrike_Reports/5599_hosts_2023-07-03T16_22_12Z.csv", "crowdstrike_installed")
                    compare_data(data, "Datadog_Reports/2023-07-03_DataDog.csv", "datadog_installed")

            
        except Exception as e:
            print("Failed at loop response", "\n", e)
    
    except Exception as e:
        print("Failed to receive a 200 HTTP Request", "\n", e)

    end = time()
    print(f"{api_table_name} : Thread {thread_number} completed in : {int(end - start)} seconds")