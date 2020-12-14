import socket
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from client_crypto_utils import *

if __name__ == "__main__":
    # Assume this would be available on a public server website or maybe emailed to each user
    # So that the user can know they are connecting to the right server.
    server_public_key = b"4Qxvc_E79yz7sDKca2Upaw_W9q562TAriE_f5ETM7iI="

    
    client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    client_public_key = client_private_key.public_key()

    clientSocket = socket.socket()
    ip = 'localhost'
    port = 25554
    ### Set up connection to server
    clientSocket.connect((ip, port))
    print(clientSocket.recv(1024).decode('utf-8'))

    # Send encrypted auth messaged 
    f = Fernet(server_public_key)
    auth = f.encrypt(b"auth")
    clientSocket.send(auth)
    authentication = clientSocket.recv(1024).decode('utf-8')

    if authentication != "Authed":
        print("Couldn't authenticate server connection!")
        sys.exit("")
    print("Connect Authenticated! You are connected to the right server.")
    if len(sys.argv)>1:
        if sys.argv[1] in ["-r", "-R"]:
            print("")
            print("Enter registration info: ")
            clientSocket.send("registering".encode('utf-8'))
            user = input(clientSocket.recv(1024).decode('utf-8'))
            clientSocket.send(user.encode('utf-8'))
            password = input(clientSocket.recv(1024).decode('utf-8'))
            clientSocket.send(password.encode('utf-8'))
            role = input(clientSocket.recv(1024).decode('utf-8'))
            clientSocket.send(role.encode('utf-8'))
            
            print(clientSocket.recv(1024).decode('utf-8'))
            clientSocket.close()
            sys.exit()
        else:
            clientSocket.send("logging".encode('utf-8'))
    else:
        clientSocket.send("logging".encode('utf-8'))

    ### Log in if the connection is authentic
    print("")
    print("Enter log in info: ")
    user = input(clientSocket.recv(1024).decode('utf-8'))
    clientSocket.send(user.encode('utf-8'))
    password = input(clientSocket.recv(1024).decode('utf-8'))
    clientSocket.send(password.encode('utf-8'))
    
    logged_in = clientSocket.recv(1024).decode('utf-8')
    if logged_in != "valid login":
        print("Unsuccessful login, try again.")
        sys.exit("")
    print("\nSuccesfully logged in!")

    ### Set up connection between this and the other client
    client_setting = input(clientSocket.recv(1024).decode('utf-8')).lower()
    clientSocket.send(client_setting.encode('utf-8'))

    if client_setting == "c":
        while True:
            choose_user = input(clientSocket.recv(1024).decode('utf-8')).lower()
            clientSocket.send(choose_user.encode('utf-8'))
            if choose_user != "w":
                break
                
    elif client_setting == "r":
        print("\nWaiting to recieve connection..")
    else:
        sys.exit("Please prove the correct setting")
    

    # Sending the public and private key.
    client_public_key_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.PKCS1)

    if client_setting == "c":
        clientSocket.send(client_public_key_bytes)
        other_client_public_key_bytes = clientSocket.recv(8192)
    else:
        other_client_public_key_bytes = clientSocket.recv(8192)
        clientSocket.send(client_public_key_bytes)
    ### Connection confirmed secured, at this point each client has the other's public key
    other_client_public_key = load_pem_public_key(other_client_public_key_bytes, backend=default_backend())
    if client_setting == "c":
        print(clientSocket.recv(8192).decode('utf-8'))
    else:
        print("\nPublic and Private keys exchanged, communication secure!\n")
    
    if client_setting == "c":        
        print("You are call, you will be first (while taking turns) to message in this session.\n")
        while True:
            msg = input('You: ')
            clientSocket.send(msg_encrypt(msg, other_client_public_key))
            response = clientSocket.recv(8192)
            print("Them: "+msg_decrypt(response, client_private_key))
    else:
        print("You are receiving, you will be second (while taking turns) to message in this session.\n")
        while True:
            response = clientSocket.recv(8192)
            print("Them: "+msg_decrypt(response, client_private_key))
            msg = input('You: ')
            clientSocket.send(msg_encrypt(msg, other_client_public_key))

    clientSocket.close()
    print("Execution finished.")