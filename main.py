import scapy.all as sc
import socket
import threading
import sqlite3
#import time
#import paramiko

flag = True

def databaseConnection(ip,port):        #function to connect and save data to local database
    db = sqlite3.connect("data.db")     #creating/opening local database
    cur = db.cursor()                   #creating cursor
    global flag
    try:
        if flag:
            cur.execute("create table log(ip varchar(15), port int(4));")   #create new table if not exists
            db.commit()
            flag = False                #set flag to true after table creation
    except:
        flag = False                    #set flag to true if table exits
    cur.execute(f"insert into log values(\"{ip}\",{port});")                 #writing data
    db.commit() 
    db.close()                          #closing database
    print(f"[-] From {ip} to {port}")

class deepPacket:                       #packet monitoring class
        
    def filterConnection(packets):      
        for packet in packets:      #ilterating packets / connections
            try:
                try:
                    if packet[2].dport in [21,22,23,80,443,3306]:   #port is in layer 2 
                        ip = packet[1].src                          #ip address is in layer 1
                        port = packet[2].dport
                        databaseConnection(ip,port)                 #passing data
                except AttributeError or ValueError:
                    pass
            except IndexError:
                pass
            packet = None

    def monitorConnections():
        try:
            try:
                while True:
                    packet = sc.sniff(count = 20, timeout = 5)      #sniffing packet using scapy till 20 packets or 5 seconds
                    t = threading.Thread(target = deepPacket.filterConnection, args = (packet,) )   #creating a new thread for packet classification
                    t.start()   #starting thread
            except AttributeError:
                pass
        except ValueError:
            pass
deepPacket.monitorConnections()
