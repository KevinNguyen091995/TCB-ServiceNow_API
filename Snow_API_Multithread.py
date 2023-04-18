from Snow_API_Connector import *
import asyncio
import threading

def callback_thread(function, *args):
    asyncio.run(function(*args))

def get_count_vulnerability_thread_call():
    total_threads = 8
    get_entry_count_vulnerability()

    for thread in range(total_threads):
        threader = threading.Thread(target=callback_thread, args=(get_count_vulnerability, (len(vul_entry_dict) / total_threads) * thread, thread+1, total_threads))
        threader.start()

def get_cmdb_server_list_thread_call():
    total_threads = 4

    for thread in range(total_threads):
        threader = threading.Thread(target=callback_thread, args=(get_cmdb_server, (thread * 1000), thread+1))
        threader.start()