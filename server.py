import socket
import threading
import json
import hmac
import os
import base64
from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def generate_pub_prv_key():
    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
    
    SERVER_PRIVATE_KEY = RSA.generate(8192)
    SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.publickey()

    password = input("Enter private key password: ")

    hashed_password = hashlib.sha256(password.encode()).digest()

    ciphered_private_key = SERVER_PRIVATE_KEY.export_key(passphrase=hashed_password, pkcs=8, protection="scryptAndAES128-CBC")

    with open("encrypted_private_key.pem", "wb") as file:
        file.write(ciphered_private_key)

    with open("public_key.pem", "wb") as file:
        file.write(SERVER_PUBLIC_KEY.export_key())

def load_pub_prv_key():

    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY

    password = input("Enter private key password: ")
    hashed_password = hashlib.sha256(password.encode()).digest()
    
    with open("encrypted_private_key.pem", "rb") as file:
        encrypted_data = file.read()

    SERVER_PRIVATE_KEY = RSA.import_key(encrypted_data, passphrase=hashed_password)

    with open("public_key.pem", "rb") as file:
        public_key = file.read()
        SERVER_PUBLIC_KEY = RSA.import_key(public_key)

USERS_FILE = "users.json"  # JSON file to store registered users
connected_clients = {}
groups = {}
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = None, None
AES_KEY_PASSWORD = b'ServerPrivateKey'  # Private key for encryption

GENERATE_PUB_PRV_KEY_RSA = 0 # will be 1 for running again and generate new pair of private/public RSA server key
if GENERATE_PUB_PRV_KEY_RSA:
    generate_pub_prv_key()

load_pub_prv_key()

def load_users():
    try:
        with open(USERS_FILE, "r") as file:
            users = json.load(file)
    except FileNotFoundError:
        users = {}
    return users

users = load_users()

def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file)

def encrypt_password(password):
    cipher = AES.new(AES_KEY_PASSWORD, AES.MODE_ECB)
    encrypted_password = cipher.encrypt(pad(password.encode(), AES.block_size))
    return encrypted_password

def decrypt_password(encrypted_password):
    cipher = AES.new(AES_KEY_PASSWORD, AES.MODE_ECB)
    decrypted_password = unpad(cipher.decrypt(encrypted_password), AES.block_size)
    return decrypted_password.decode()

def secure_send_message(conn, cipher, data):
    hmac_digest = hmac.new(b'', data["type"].encode(), digestmod='sha256').digest()
    data['hmac'] = hmac_digest.hex()
    json_data = json.dumps(data).encode()
    
    conn.send(cipher.encrypt(json_data))

def exchange_public_key(conn, client_address):
    conn.send(SERVER_PUBLIC_KEY.export_key())
    server_certificate = {
        'id': "server",
        'public_key': SERVER_PUBLIC_KEY.export_key().decode()
    }
    server_certificate = json.dumps(server_certificate).encode()
    conn.send(server_certificate)
    
    cipher_server = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)
    client_public_key = RSA.import_key(conn.recv(65536))
    certificate_client = json.loads(conn.recv(65536).decode())
    if certificate_client["id"] == "client" and client_public_key == RSA.import_key(certificate_client["public_key"].encode()):
        print("Client {}:{} public key certificate is ok.".format(client_address[0], client_address[1]))
    else:
        print("Client {}:{} public key certificate was not ok.".format(client_address[0], client_address[1]))
        return None, None, None, None
    cipher_client = PKCS1_OAEP.new(client_public_key)

    return cipher_server, cipher_client, client_public_key, certificate_client

def handle_client(conn, client_address):
    cipher_server = None
    while cipher_server == None:
        cipher_server, cipher_client, client_public_key, certificate_client = exchange_public_key(conn, client_address)

    while True:
        rcv_data = conn.recv(65536)
        try:
            decrypted_data = cipher_server.decrypt(rcv_data)
            data = json.loads(decrypted_data.decode())
            received_hmac = bytes.fromhex(data['hmac'])
            received_command = data['command']
            command = data['command']
            hmac_digest = hmac.new(b'', received_command.encode(), digestmod='sha256').digest()
        except:
            a = cipher_server.decrypt(rcv_data).decode()
            # a = json.loads(rcv_data.decode('utf-8'))
            print(a)
            continue

        # if hmac.compare_digest(received_hmac, hmac_digest):
        #     print("Received from client {}:{}".format(client_address[0], client_address[1]) + " - " + received_message)
        # else:
        #     print('HMAC verification failed!')
        #     continue
        
        if command == "exchange_key2":
            #TODO
            print()

        content = data["message"]
        
        if command == "online-users":
            username = content
            online_users = [key for key, value in connected_clients.items() if value.get("conn") is not None and key != username]
            response = {"type": "success", "content": "Online Users:\n" + '\n'.join(online_users)}
        elif command == "register":
            username, password = content.split(",")
            if username in users:
                response = {"type": "fail", "message": "Username already exists. Please choose a different username."}
            else:
                encrypted_password = str(encrypt_password(password))
                users[username] = encrypted_password
                save_users(users)
                response = {"type": "success", "message": "Registration successful. You can now login."}
        elif command == "login":
            username, password = content.split(",")
            encrypted_password = encrypt_password(password)
            if username in users and users[username] == str(encrypted_password):
                response = {"type": "success", "message": "Login successful. Welcome, {}!".format(username)}
                connected_clients[username] = {
                    "conn": conn,
                    "cipher": cipher_client,
                    "public_key": client_public_key,
                    "certificate": certificate_client
                }
            else:
                response = {"type": "fail", "message": "Invalid username or password. Please try again."}
        elif command == "logout":
            username = content
            connected_clients.get(username, {})["conn"] = None
            response = {"type": "success", "message": "Logout successful. Goodby, {}!".format(username)}
        elif command == "DH_1": # Diffie-Hellman
            sender, receiver = content.split(",")
            if sender in connected_clients and receiver in connected_clients:
                receiver_conn = connected_clients[receiver]["conn"]
                receiver_cipher = connected_clients[receiver]["cipher"]
                # data['pub_key_RSA_sender'] = client_public_key.export_key().decode()
                data['type'] = "DH_1"
                del data['command']
                secure_send_message(receiver_conn, receiver_cipher, data)
                response = {"type": "succes", "message": f"Send request to {receiver} successfully."}
        elif command == "DH_2":
            sender, receiver = content.split(",")
            encrypted_data = conn.recv(2048).decode('utf-8')
            conn_receiver, cipher_receiver = connected_clients[receiver]["conn"], connected_clients[receiver]["cipher"]
            response = {"type": "DH_2", "sender": sender}
            secure_send_message(conn_receiver, cipher_receiver, response)
            conn_receiver.send(encrypted_data)
            response = {"type": "succes", "message": f"Send DH-Params to {receiver} successfully."}
        elif command == "message":
            sender, receiver, message = content.split(",", 2)
            if sender in connected_clients and receiver in connected_clients:
                receiver_conn = connected_clients[receiver]["conn"]
                receiver_cipher = connected_clients[receiver]["cipher"]
                message = {"type": "success", "message": f"Message from {sender}: {message}"}
                secure_send_message(receiver_conn, receiver_cipher, message)
                response = {"type": "success", "message": "Message sent successfully."}
            else:
                response = {"type": "fail", "message": "Sender or receiver is not logged in."}
        elif command == "end2end":
            sender, receiver = content.split(",")
            end2end_encrypted_message = conn.recv(1024)
            conn_receiver, cipher_receiver = connected_clients[receiver]["conn"], connected_clients[receiver]["cipher"]
            response = {"type": "end2end", "sender": sender}
            secure_send_message(conn_receiver, cipher_receiver, response)
            conn_receiver.send(end2end_encrypted_message)
            response = {"type": "success", "message": "Message sent E2E successfully"}
        elif command == "create_group":
            group_name, username = content.split(",")
            if group_name in groups:
                response = {"type": "fail", "message": "Group name already exists. Please choose a different group name."}
            elif username not in users:
                response = {"type": "fail", "message": "Invalid username. Please log in first."}
            else:
                groups[group_name] = {"admin": [username], "members": [username]}
                response = {"type": "success", "message": "Group '{}' created successfully.".format(group_name)}
        elif command == "send_group_message":
            group_name, username, message = content.split(",", 2)
            if group_name in groups and username in groups[group_name]["members"]:
                for member in groups[group_name]["members"]:
                    if member in connected_clients and member != username:
                        member_conn = connected_clients[member]["conn"]
                        member_cipher = connected_clients[member]["cipher"]
                        message = {"type": "success", "message": f"Group '{group_name}': message from {username}: {message}"}
                        secure_send_message(member_conn, member_cipher, message)
                response = {"type": "success", "message": "Message sent successfully."}
            else:
                response = {"type": "fail", "message": "You are not a member of the group or the group does not exist."}
        elif command == "add_group_member":
            group_name, username, new_member = content.split(",", 2)
            if group_name in groups and username in groups[group_name]["admin"] and new_member in users:
                groups[group_name]["members"].append(new_member)
                for member in groups[group_name]["members"]:
                    if member in connected_clients:
                        member_conn = connected_clients[member]["conn"]
                        member_cipher = connected_clients[member]["cipher"]
                        message = {"type": "success", "message": f"Group '{group_name}': Member {new_member} added to group"}
                        secure_send_message(member_conn, member_cipher, message)
                response = {"type": "success", "message":  "Member added successfully".format(new_member, group_name)}
            else:
                response = {"type": "fail", "message":  "You are not a member of the group or the group or username does not exist."}
        elif command == "add_group_admin":
            group_name, username, new_admin = content.split(",", 2)
            if (
                group_name in groups
                and username in groups[group_name]["admin"]
                and new_admin in groups[group_name]["members"]
            ):
                groups[group_name]["admin"].append(new_admin)
                response = {"type": "success", "message":  "Member '{}' is now an admin of group '{}'.".format(new_admin, group_name)}
            else:
                response = {"type": "fail", "message":  "You are not an admin or a member of the group or the group or username does not exist."}
        else:
                response = {"type": "fail", "message":  "Unsupported command."}

        secure_send_message(conn, cipher_client, response)
        
    conn.close()

def server_program():
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    server_socket.bind((host, port))  # bind host address and port together

    server_socket.listen(3)
    print("Server listening on {}:{}".format(host, port))

    while True:
        conn, address = server_socket.accept()  # accept new connection
        print("Connection established with {}:{}".format(address[0], address[1]))

        client_thread = threading.Thread(target=handle_client, args=(conn, address))
        client_thread.start()

if __name__ == '__main__':
    server_program()