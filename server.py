import socket
import ssl
import os
import sys
import _thread
import time
import queue
from server_crypto_utils import *
from cryptography.fernet import Fernet
import asyncio

thread_id = 0
firstConn = queue.Queue()
secondConn = queue.Queue()
onlineUsers = queue.Queue()
other_username = queue.Queue()

# Assume this would be available on a public server website or maybe emailed to each user
# So that the user can know they are connecting to the right server.
server_public_key = b"4Qxvc_E79yz7sDKca2Upaw_W9q562TAriE_f5ETM7iI="

def multi_thread(conn, thread_id):
    ### Set up connection 
    conn.send(b"Attempting Connection Authentication..")
    encrypted_auth = conn.recv(2048)

    try: 
        f = Fernet(server_public_key)
        if f.decrypt(encrypted_auth) == b"auth": 
            conn.send(b"Authed")
        else:
            conn.send(b"Not Authed")
            conn.close()
            return
    except:
        conn.send(b"Not Authed")
        conn.close()
        return 

    mode = conn.recv(2048).decode('utf-8')

    ### Registration
    if mode == "registering":
        conn.send(b"Enter username: ")
        user = conn.recv(2048).decode('utf-8')
        conn.send(b"Enter password: ")
        password = conn.recv(2048).decode('utf-8')
        conn.send(b"Enter role (admin, guest, user): ")
        role = conn.recv(2048).decode('utf-8')
        
        hashed_pass = hash_pass(password)
        writeAccount = open("accounts.txt","a")
        writeAccount.write(user + "," + hashed_pass + "," + role+"\n")
        writeAccount.close()

        conn.send(b"\nSuccessfully registered! You can now log in when running the program. ")
        login = conn.recv(2048).decode('utf-8')
        conn.close()
        return

    ### Logging in 
    if mode == "logging":
        conn.send(b"Enter username: ")
        user = conn.recv(2048).decode('utf-8')
        conn.send(b"Enter password: ")
        password = conn.recv(2048).decode('utf-8')
        
        if valid_login(user, password):
            conn.send(b"valid login")
            onlineUsers.put(user)
        else:
            conn.send(b"not valid login")
            conn.close()

        ### Set up connection between two clients
        conn.send(b"Are you recieving or starting [r/c]: ")
        call_setting = conn.recv(2048).decode('utf-8')
        all_users=[]
        second = False
        if call_setting == "c":
            other_username.put(user)
            while True:
                user_amount = onlineUsers.qsize()
                for _ in range(user_amount):
                    other_user = onlineUsers.get_nowait()
                    if other_user != user:
                        all_users.append(other_user)
                for i in range(user_amount - 1):
                    onlineUsers.put(all_users[i])
                onlineUsers.put(user)

                question = "Which user do you want to connect to?\n"+str(all_users)+"\nType their name or w to wait: "
                conn.send(question.encode('utf-8'))
                other_user = conn.recv(2048).decode('utf-8')
                firstConn.put(conn)
                second = True
                if other_user != "w" and other_user != "wait":
                    break
                time.sleep(1)

        elif call_setting == "r":
            other_user = other_username.get()
            secondConn.put(conn)

        try:
            if second:
                other_conn = secondConn.get()
            else:
                other_conn = firstConn.get()
        except: 
            sys.exit("error, set up both connections first !")
        
        if second:
            public_key = conn.recv(8192)
            other_conn.send(public_key)
            public_key = other_conn.recv(8129)
            conn.send(public_key)
        else:
            while True:
                pass

        conn.send(b"\nPublic and Private keys exchanged, communication secure!\n")
        if second:
            while True:
                msg = conn.recv(8192)
                other_conn.send(msg)
                print(msg)
                
                msg = other_conn.recv(8192)
                conn.send(msg)
                print(msg)
        else:
            while True:
                pass
    conn.close()

if __name__ == "__main__":
    while True:
        ip = "localhost"
        port = 25554
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind((ip, port))
        serverSocket.listen(20)

        conn, address = serverSocket.accept()
        _thread.start_new_thread(multi_thread, (conn, thread_id))
        thread_id += 1 
    serverSocket.close()