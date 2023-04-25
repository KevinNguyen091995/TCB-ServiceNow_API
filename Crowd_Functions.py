from Key_Functions_Modules import *
import Database.DB_Connection as DC
import queue
import ipaddress

total_cidr_array = queue.Queue()

def insert_crowdstrike():
    cnxn, cursor = DC.new_database_connection()

    with open('3574_hosts_2023-03-31T16_30_25Z.csv', 'r') as csvfile:
        csvreader = csv.reader(csvfile)

        headers = next(csvreader)

        query = "INSERT INTO crowdstrike ({}) VALUES ({})".format('.'.join(headers), '.'.join('?' for i in range(len(headers))))

        for row in csvreader:
            row[0] = encrypt_data(row[17].lower().encode())
            row[17] = encrypt_data(row[17].lower().encode())
            row[18] = encrypt_data(row[18].lower().encode())
            row[19] = encrypt_data(row[19].lower().encode())
            row[20] = encrypt_data(row[20].lower().encode())

            sql_insert = 'INSERT INTO crowdstrike VALUES ('
            for value in row:
                sql_insert += '?, '

            sql_insert = sql_insert[:-2] + ')'

            cursor.execute(sql_insert, row)
            cnxn.commit()

        cnxn.close()

def get_total_cidr():
    global total_cidr_array

    with open('cidrs.csv', 'r', encoding="utf-8") as csvfile:
        csvreader = csv.reader(csvfile, delimiter="\t")
        for row in csvreader:
            total_cidr_array.put(row[2])

    return total_cidr_array

async def get_cidr_ip_address(thread):
    cnxn, cursor = DC.new_database_connection()

    while total_cidr_array.qsize() != 0:
        cidr = total_cidr_array.get()
        print(f"Thread : {thread} still in progress")
        encrypt_cidr = encrypt_data(cidr.encode())
        for ip in ipaddress.IPv4Network(cidr):
            encrypt_ip = encrypt_data(str(ip).encode())

            cursor.execute("INSERT INTO cidr_list VALUES (?,?)",  encrypt_cidr, encrypt_ip)
            cnxn.commit()

    print(f"Thread - {thread} has completed...")

    cnxn.close()

def get_cidr_thread_call():
    total_threads = 16
    thread_array = []

    for thread in range(total_threads):
        thread_array.append(threading.Thread(target=callback_thread, args=(get_cidr_ip_address, thread)))
        thread_array[-1].start()

    for join_thread in thread_array:
        join_thread.join()

def get_notation_data():
    cnxn, cursor = DC.new_database_connection()

    cidr_map = dict()

    cidr_join = cursor.execute("""
        SELECT DISTINCT cidr.cidr_notation, COUNT(cidr.cidr_notation) FROM cidr_list as cidr

        RIGHT JOIN snow_cmdb_list
        ON snow_cmdb_list.snow_computer_ip_address = cidr.cidr_ip_address

        WHERE snow_operational_status = 'Operational'

        GROUP BY cidr.cidr_notation""")

    for row in cidr_join:
        if row[0] != None:
            cidr_map.update({decrypt_data(row[0]) : row[1]})

    for x,y in cidr_map.items():
        print(x, y)