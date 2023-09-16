import scapy.all as sc
import socket
import threading
import sqlite3
#import time
#import paramiko

flag = True

def databaseConnection(ip,port):
    db = sqlite3.connect("data.db")
    cur = db.cursor()
    global flag
    if flag:
        cur.excute("create table log(ip varchar(15), port int(4));")
        db.commit()
        flag = False
    except:
        flag = False
    cur.execute(f"insert into log values(\"{ip}\",{port});")
    db.commit()
    db.close()
    print(f"[-] From {ip} to {port}")

class deepPacket:

    def __init__(self):
        pass
    
    def filterConnection(self,packets):
        for packet in packets:
            if packet[2].dport in [21,22,23,80,443,3306]:
                ip = packet[1].src
                port = packet[2].dport
                databaseConnection(ip,port)

    def monitorConnections(self):
        try:
            while True:
                packet = sc.sniff(count = 20, timeout = 5)
                t = threading.Thread(target = self.filterConnection, args = (packet,) )
                t.start()
        except:
            pass

