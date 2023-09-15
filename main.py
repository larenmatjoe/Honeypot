import scapy.all as sc
import socket
import threading
import sqlite3
#import time
#import paramiko

flag = True

class deepPacket:
    
    def filterConnection(packets):
        for packet in packets:
            if packet[2].dport in [21,22,23,80,443,3306]:
                ip = packet[1].src
                port = packet[2].dport
                databaseConnection(ip,port)
