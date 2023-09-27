import scapy.all as sc
import socket
import threading
import sqlite3
#import time
#import paramiko

flag = True
class dataBase:
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

    def databaseAuthConnection(ip,port,username,password):
        db = sqlite3.connect("data.db")
        cur = db.cursor()
        global flag1
        try:
            if flag:
                cur.execute("create table auth(ip varchar(15), port int(4), username varchar(30), password varchar(60));")
                db.commit()
                flag1 = False
        except:
            flag = False
        cur.execute(f"insert into auth values(\"{ip\",{port},\"{username}\",\"{password}\");")
        db.commit()
        db.close()

class deepPacket:                       #packet monitoring class
        
    def filterConnection(packets):      
        for packet in packets:      #ilterating packets / connections
            try:
                try:
                    if packet[2].dport in [21,22,23,80,443,3306]:   #port is in layer 2 
                        ip = packet[1].src                          #ip address is in layer 1
                        port = packet[2].dport
                        dataBase.databaseConnection(ip,port)                 #passing data
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

class servers:          #code not tested
    def telnet():
        ip = "127.0.0.1"
        server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.bind((ip,23))
        server.listen(3)
        connection , address = server.accept()
        connection.send(b"Welcome to Telnet Server \n")
        connection.send(b"======================== \n")
        connection.send(b"Username: ")
        username = connection.recv(1024)
        connection.send(b"Password: ")
        password = connection.recv(1024)
        connection.send(b"Authentication Error")
        connection.close()
        username = username.strip()
        username = username.decode()
        password = password.decode()
        databaseAuthConnection(address[0],address[1],username,password)
        print(username + " : " + password)

#deepPacket.monitorConnections()
servers.telnet()
