from Key_Functions_Modules import *
import pysnow

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