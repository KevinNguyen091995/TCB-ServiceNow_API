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

def get_cmdb_server_list_thread_call():
    print("Starting CMDB Server")
    total_threads = 16
    thread_array = []

    for thread in range(total_threads):
        thread_array.append(threading.Thread(target=callback_thread, args=(get_cmdb_server, (thread * 1000), thread+1)))
        thread_array[-1].start()

    for join_thread in thread_array:
        join_thread.join()

def get_cmdb_computer_list_thread_call():
    print("Starting CMDB Computer")
    total_threads = 10
    thread_array = []

    for thread in range(total_threads):
        thread_array.append(threading.Thread(target=callback_thread, args=(get_cmdb_computer, (thread * 2000), thread+1)))
        thread_array[-1].start()

    for join_thread in thread_array:
        join_thread.join()