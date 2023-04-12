import threading
import asyncio
from Snow_API_Connector import *

def get_count_vulnerability_thread(*args):
    asyncio.run(get_count_vulnerability(*args))

if __name__ == '__main__':
    get_entry_count_vulnerability()

    get_count_thread_1 = threading.Thread(target=get_count_vulnerability_thread, args=((len(vul_entry_dict) / 4) * 0, 1, 4))
    get_count_thread_2 = threading.Thread(target=get_count_vulnerability_thread, args=((len(vul_entry_dict) / 4) * 1, 2, 4))
    get_count_thread_3 = threading.Thread(target=get_count_vulnerability_thread, args=((len(vul_entry_dict) / 4) * 2, 3, 4))
    get_count_thread_4 = threading.Thread(target=get_count_vulnerability_thread, args=((len(vul_entry_dict) / 4) * 3, 4, 4))

    get_count_thread_1.start()
    get_count_thread_2.start()
    get_count_thread_3.start()
    get_count_thread_4.start()