from Snow_API_Connector import *

def get_count_vulnerability_thread_call():
    print("Starting SN Vulnerability")
    get_entry_count_vulnerability()

    total_threads = 8
    thread_array = []

    for thread in range(total_threads):
        thread_array.append(threading.Thread(target=callback_thread, args=(get_count_vulnerability, (len(vul_entry_dict) / total_threads) * thread, thread+1, total_threads)))
        thread_array[-1].start()

    for join_thread in thread_array:
        join_thread.join()

def get_api_thread():
    total_threads = 16
    thread_array = []
    thread_lock = threading.Lock()

    def generate_report(sheet_name, api_name):
        dataframe = {
            "cmdb_ci_computer" : get_computer_dataframe(),
            "cmdb_ci_win_server" : get_window_dataframe(),
            "cmdb_ci_linux_server" : get_linux_dataframe(),
            "cmdb_ci_esx_server" : get_esx_dataframe(),
        }

        good, review, retired = get_total_class_count_mapping(api_name)
        software_installed, supported, location, managed_by, managed_by_group = get_total_field_count_mapping(api_name)

        print(software_installed, supported, location, managed_by, managed_by_group)

        write_to_excel(sheet_name, dataframe.get(api_name))
        write_to_text(api_name, good, review, retired, software_installed, supported, location, managed_by, managed_by_group)


    #Names of APIs currently used
    #['cmdb_ci_computer', 'cmdb_ci_win_server', 'cmdb_ci_linux_server', 'cmdb_ci_esx_server']

    for thread in range(total_threads):
        thread_array.append(threading.Thread(target=callback_thread, args=(get_api_asset, "cmdb_ci_computer", (thread * 5), 5, thread+1, thread_lock)))
        sleep(.1)
        thread_array[-1].start()

    for join_thread in thread_array:
        join_thread.join()

    #Workstations
    generate_report("Workstation", "cmdb_ci_computer")

    #Windows Server
    generate_report("Window Server", "cmdb_ci_win_server")

    #Linux Server
    generate_report("Linux Server", "cmdb_ci_linux_server")

    #ESX Server
    generate_report("ESX Server", "cmdb_ci_esx_server")