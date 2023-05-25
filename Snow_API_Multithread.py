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
    global full_dataframe

    total_threads = 2
    thread_array = []

    for thread in range(total_threads):
        thread_array.append(threading.Thread(target=callback_thread, args=(get_api_asset, "cmdb_ci_computer", (thread * 1), 1, thread+1)))
        sleep(.1)
        thread_array[-1].start()

    for join_thread in thread_array:
        join_thread.join()

    print(full_dataframe)

def get_server_thread_call():
    win_server = threading.Thread(target=callback_thread, args=(check_servers, cmdb_ci_win_server, "cmdb_ci_win_server"))
    linux_server = threading.Thread(target=callback_thread, args=(check_servers, cmdb_ci_linux_server, "cmdb_ci_linux_server"))
    unix_server = threading.Thread(target=callback_thread, args=(check_servers, cmdb_ci_unix_server, "cmdb_ci_unix_server"))
    esx_server = threading.Thread(target=callback_thread, args=(check_servers, cmdb_ci_esx_server, "cmdb_ci_esx_server"))

    win_server.start()
    sleep(1)
    linux_server.start()
    sleep(1)
    unix_server.start()
    sleep(1)
    esx_server.start()