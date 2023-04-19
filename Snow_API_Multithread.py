from Snow_API_Connector import *
import asyncio
import threading

def callback_thread(function, *args):
    asyncio.run(function(*args))

def get_count_vulnerability_thread_call():
    get_entry_count_vulnerability()

    total_threads = 8
    thread_array = []

    for thread in range(total_threads):
        thread_array.append(threading.Thread(target=callback_thread, args=(get_count_vulnerability, (len(vul_entry_dict) / total_threads) * thread, thread+1, total_threads)))
        thread_array[-1].start()

    for join_thread in thread_array:
        join_thread.join()

def get_cmdb_server_list_thread_call():
    total_threads = 4
    thread_array = []

    for thread in range(total_threads):
        thread_array.append(threading.Thread(target=callback_thread, args=(get_cmdb_server, (thread * 1000), thread+1)))
        thread_array[-1].start()

    for join_thread in thread_array:
        join_thread.join()

def get_cmdb_computer_list_thread_call():
    total_threads = 2
    thread_array = []


    for thread in range(total_threads):
        thread_array.append(threading.Thread(target=callback_thread, args=(get_cmdb_computer, (thread * 1000), thread+1)))
        thread_array[-1].start()

    for join_thread in thread_array:
        join_thread.join()