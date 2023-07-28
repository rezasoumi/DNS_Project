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
from Crypto.Hash import SHA256
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from Crypto.Signature import PKCS1_v1_5
import time
import random

def generate_pub_prv_key():
    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
    
    SERVER_PRIVATE_KEY = RSA.generate(8192)
    SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.publickey()

    password = input("Enter private key password: ")

    hashed_password = hashlib.sha256(password.encode()).digest()

    ciphered_private_key = SERVER_PRIVATE_KEY.export_key(passphrase=hashed_password, pkcs=8, protection="scryptAndAES128-CBC")

    with open("Keys/encrypted_private_key.pem", "wb") as file:
        file.write(ciphered_private_key)

    with open("Keys/public_key.pem", "wb") as file:
        file.write(SERVER_PUBLIC_KEY.export_key())

def load_pub_prv_key():

    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY

    password = input("Enter private key password: ")
    hashed_password = hashlib.sha256(password.encode()).digest()
    
    with open("Keys/encrypted_private_key.pem", "rb") as file:
        encrypted_data = file.read()

    SERVER_PRIVATE_KEY = RSA.import_key(encrypted_data, passphrase=hashed_password)

    with open("Keys/public_key.pem", "rb") as file:
        public_key = file.read()
        SERVER_PUBLIC_KEY = RSA.import_key(public_key)

USERS_FILE = "users.json"  # JSON file to store registered users
connected_clients = {}
groups = {}
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = None, None
AES_KEY_PASSWORD = b'ServerPrivateKey'  # Private key for encryption
verifier = None
tcp_seq_num = {}
offline_messages = {}

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
    data['tcp_seq_num'] = tcp_seq_num[conn]["send"]
    tcp_seq_num[conn]["send"] += 1
    if tcp_seq_num[conn]["send"] > 100000:
        tcp_seq_num[conn]["send"] = 0
    json_data = json.dumps(data).encode()
    
    conn.send(cipher.encrypt(json_data))

def exchange_public_key(conn, client_address):
    global verifier
    conn.send(SERVER_PUBLIC_KEY.export_key())
    tcp_seq_num[conn] = {}
    tcp_seq_num[conn]["receive"] = random.randint(0, 100000)
    server_certificate = {
        'id': "server",
        'public_key': SERVER_PUBLIC_KEY.export_key().decode(),
        'tcp_seq_num': tcp_seq_num[conn]["receive"]
    }
    server_certificate = json.dumps(server_certificate).encode()
    conn.send(server_certificate)
    
    cipher_server = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)
    client_public_key = RSA.import_key(conn.recv(65536))
    certificate_client = json.loads(conn.recv(65536).decode())
    if certificate_client["id"] == "client" and client_public_key == RSA.import_key(certificate_client["public_key"].encode()):
        print("Client {}:{} public key certificate is ok.".format(client_address[0], client_address[1]))
        tcp_seq_num[conn]["send"] = certificate_client['tcp_seq_num']
    else:
        print("Client {}:{} public key certificate was not ok.".format(client_address[0], client_address[1]))
        return None, None, None, None
    cipher_client = PKCS1_OAEP.new(client_public_key)
    verifier = PKCS1_v1_5.new(client_public_key)

    return cipher_server, cipher_client, client_public_key, certificate_client

def get_user_name(conn):
    for key, value in connected_clients.items():
        if conn == value['conn']:
            return key
    return None

def handle_client(conn, client_address):
    cipher_server = None
    while cipher_server == None:
        cipher_server, cipher_client, client_public_key, certificate_client = exchange_public_key(conn, client_address)

    while True:
        try:
            print(f"client: {get_user_name(conn)}")
            
            rcv_data = conn.recv(65536)
            time.sleep(0.2)
            try:
                d = cipher_server.decrypt(rcv_data).decode()
            except:
                continue
            rcv_sign = conn.recv(65536) 
            decrypted_data = cipher_server.decrypt(rcv_data)
            data = json.loads(decrypted_data.decode())
            command = data['command']
            
            is_valid = verifier.verify(SHA256.new(decrypted_data), rcv_sign)
            if is_valid:
                print("Signature is valid. The message was signed by Alice.")
            else:
                print("Signature is invalid. The message may have been tampered with or not signed by Alice.")
            if data['tcp_seq_num'] == tcp_seq_num[conn]["receive"]:
                    print("The message is New.")
                    tcp_seq_num[conn]["receive"] += 1
                    if tcp_seq_num[conn]["receive"] > 100000:
                        tcp_seq_num[conn]["receive"] = 0
            else:
                print("The message is not New.")

            print(data)
            content = data["message"]
            
            if command == "online-users":
                username = content
                online_users = [key for key, value in connected_clients.items() if value.get("conn") is not None and key != username]
                response = {"type": "success", "message": "Online Users:\n" + '\n'.join(online_users)}
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
                    secure_send_message(conn, cipher_client, response)
                    if username not in offline_messages:
                        offline_messages[username] = []
                    else:
                        for m in offline_messages[username]:
                            secure_send_message(conn, cipher_client, m)
                            time.sleep(0.5)
                else:
                    response = {"type": "fail", "message": "Invalid username or password. Please try again."}
                    secure_send_message(conn, cipher_client, response)
                continue
            elif command == "logout":
                username = content
                connected_clients.get(username, {})["conn"] = None
                response = {"type": "success", "message": "Logout successful. Goodby, {}!".format(username)}
            elif command == "send_to_offline":
                sender, receiver, message = content.split(",", 2)
                if sender in connected_clients and receiver in connected_clients:
                    receiver_cipher = connected_clients[receiver]["cipher"]
                    data = {
                        "type": command,
                        "sender": sender,
                        "message": message
                    }
                    offline_messages[receiver].append(data)
                    response = {"type": "success", "message": f"Message will send to {receiver}!"}
                else:
                    response = {"type": "fail", "message": f"Server cannot handle this."}
            elif command == "DH_1": # Diffie-Hellman
                sender, receiver = content.split(",")
                if sender in connected_clients and receiver in connected_clients and connected_clients[receiver]['conn'] != None:
                    receiver_conn = connected_clients[receiver]["conn"]
                    receiver_cipher = connected_clients[receiver]["cipher"]
                    # data['pub_key_RSA_sender'] = client_public_key.export_key().decode()
                    data['type'] = "DH_1"
                    del data['command']
                    secure_send_message(receiver_conn, receiver_cipher, data)
                    receiver_conn.send(client_public_key.export_key())
                    response = {"type": "i_dont_want_to_show_this", "message": f"Send request to {receiver} successfully."}
                    print("DH_1 sent")
                else:
                    response = {"type": "fail", "message": f"Receiver is not online."}
            elif command == "DH_2":
                sender, receiver = content.split(",")
                encrypted_data = conn.recv(65536)
                conn_receiver, cipher_receiver = connected_clients[receiver]["conn"], connected_clients[receiver]["cipher"]
                response = {"type": "DH_2", "sender": sender}
                secure_send_message(conn_receiver, cipher_receiver, response)
                conn_receiver.send(encrypted_data)
                time.sleep(0.5)
                conn_receiver.send(client_public_key.export_key())
                response = {"type": "success", "message": f"Send DH-Params to {receiver} successfully."}
                print("DH_2 sent")
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
                end2end_encrypted_message = conn.recv(65536)
                time.sleep(0.5)
                sign_encrypted_message = conn.recv(65536)
                conn_receiver, cipher_receiver = connected_clients[receiver]["conn"], connected_clients[receiver]["cipher"]
                response = {"type": "end2end", "sender": sender}
                secure_send_message(conn_receiver, cipher_receiver, response)
                conn_receiver.send(end2end_encrypted_message)
                time.sleep(0.5)
                conn_receiver.send(sign_encrypted_message)
                response = {"type": "success", "message": "Message sent E2E successfully"}
            elif command == "change_key_req":
                client_public_key = RSA.import_key(conn.recv(65536))
                cipher_client = PKCS1_OAEP.new(client_public_key)
                connected_clients[content]['cipher'] = cipher_client
                connected_clients[content]['public_key'] = client_public_key
                response = {"type": "success", "message": "Your new public Key is valid and changed."}
            elif command == "create_group":
                username, group_name = content.split(",")
                if group_name in groups:
                    response = {"type": "fail", "message": "Group name already exists. Please choose a different group name."}
                else:
                    parameters = dh.generate_parameters(generator=2, key_size=512)
                    groups[group_name] = {"admins": [username], "members": [username], "parameters": parameters}
                    
                    root = parameters.parameter_numbers().p
                    generator = parameters.parameter_numbers().g
                    response = {
                        'type': "create_group",
                        'group_name': group_name,
                        'message': "Group '{}' created successfully.".format(group_name),
                        'root': root,
                        'generator': generator
                    }
                    print("Group '{}' created successfully.".format(group_name))
            elif command == "add_group_member":
                group_name, username, new_member = content.split(",", 2)
                if group_name in groups and username in groups[group_name]["admins"] and new_member in connected_clients:
                    groups[group_name]["members"].append(new_member)
                    conn_receiver, cipher_receiver = connected_clients[new_member]["conn"], connected_clients[new_member]["cipher"]
                    response = {
                        'type': "add_to_group", 
                        'group_name': group_name,
                        'root': groups[group_name]['parameters'].parameter_numbers().p,
                        'generator': groups[group_name]['parameters'].parameter_numbers().g,
                        'adder': username
                    }
                    secure_send_message(conn_receiver, cipher_receiver, response)
                    print("sent add_to_group message")

                    server_dh_pub_key_value = data['server_dh_pub_key_value']
                    parameters = groups[group_name]['parameters']
                    seq_num = random.randint(0, 100000)
                    for member in groups[group_name]["members"]:
                        Y = server_dh_pub_key_value
                        for other_member in groups[group_name]["members"]:
                            if member == other_member:
                                continue
                            response = {
                                'type': "circular_DH",
                                'admin': username,
                                'group_name': group_name,
                                'Y': Y
                            }
                            conn_receiver, cipher_receiver = connected_clients[other_member]["conn"], connected_clients[other_member]["cipher"]
                            secure_send_message(conn_receiver, cipher_receiver, response)
                            time.sleep(1)
                            rcv_data = conn_receiver.recv(65536)
                            time.sleep(1)
                            rcv_sign = conn_receiver.recv(65536)
                            # sign check verification check tcp check
                            decrypted_data = cipher_server.decrypt(rcv_data)
                            # print(json.loads(cipher_server.decrypt(rcv_sign).decode()))
                            rcv_data = json.loads(decrypted_data.decode())
                            print(rcv_data)
                            Y = rcv_data['Y']
                        
                        response = {
                            'type': 'end_circular_DH',
                            'group_name': group_name,
                            'Y': Y,
                            'tcp_seq_num_group': seq_num
                        }
                        member_conn = connected_clients[member]["conn"]
                        member_cipher = connected_clients[member]["cipher"]
                        secure_send_message(member_conn, member_cipher, response)
                        time.sleep(1)
                    for member in groups[group_name]["members"]:
                        if member != username or member != new_member:
                            mem_conn = connected_clients[member]['conn']
                            mem_cipher = connected_clients[member]["cipher"]
                            response = {"type": "success", "message": f"Group '{group_name}': Member {new_member} added to group"}
                            secure_send_message(mem_conn, mem_cipher, response)
                    response = {"type": "success", "message": f"Group '{group_name}': Member {new_member} added to group"}
                else:
                    response = {"type": "fail", "message":  "You are not a admin of the group."}
            elif command == "delete_group_member":
                group_name, username, remove_member = content.split(",", 2)
                if group_name in groups and username in groups[group_name]["admins"] and remove_member not in groups[group_name]["admins"] and remove_member in connected_clients:
                    groups[group_name]["members"] = [x for x in groups[group_name]["members"] if x != remove_member]
                    conn_receiver, cipher_receiver = connected_clients[remove_member]["conn"], connected_clients[remove_member]["cipher"]
                    response = {
                        'type': "delete_from_group", 
                        'message': group_name,
                        'admin': username
                    }
                    secure_send_message(conn_receiver, cipher_receiver, response)
                    print("sent add_to_group message")

                    server_dh_pub_key_value = data['server_dh_pub_key_value']
                    parameters = groups[group_name]['parameters']
                    seq_num = random.randint(0, 100000)
                    for member in groups[group_name]["members"]:
                        Y = server_dh_pub_key_value
                        for other_member in groups[group_name]["members"]:
                            if member == other_member:
                                continue
                            # Code
                            response = {
                                'type': "circular_DH",
                                'admin': username,
                                'group_name': group_name,
                                'Y': Y
                            }
                            conn_receiver, cipher_receiver = connected_clients[other_member]["conn"], connected_clients[other_member]["cipher"]
                            secure_send_message(conn_receiver, cipher_receiver, response)
                            time.sleep(2)
                            rcv_data = conn_receiver.recv(65536)
                            time.sleep(2)
                            rcv_sign = conn_receiver.recv(65536)
                            # sign check verification check tcp check
                            decrypted_data = cipher_server.decrypt(rcv_data)
                            rcv_data = json.loads(decrypted_data.decode())
                            print(rcv_data)
                            Y = rcv_data['Y']
                        
                        response = {
                            'type': 'end_circular_DH',
                            'group_name': group_name,
                            'Y': Y,
                            'tcp_seq_num_group': seq_num
                        }
                        member_conn = connected_clients[member]["conn"]
                        member_cipher = connected_clients[member]["cipher"]
                        secure_send_message(member_conn, member_cipher, response)
                        time.sleep(1)
                    response = {"type": "success", "message": f"Group '{group_name}': Member {remove_member} deleted from group {group_name}"}
                else:
                    response = {"type": "fail", "message":  "Invalid Operation."}
            
            elif command == "send_group_message":
                username, group_name = content.split(",")
                print(0.5)
                encrypted_message = conn.recv(65536)
                if group_name in groups and username in groups[group_name]["members"]:
                    for member in groups[group_name]["members"]:
                        if member in connected_clients and member != username:
                            member_conn = connected_clients[member]["conn"]
                            member_cipher = connected_clients[member]["cipher"]
                            response = {"type": "send_group_message", "sender": username, "message": group_name}
                            secure_send_message(member_conn, member_cipher, response)
                            member_conn.send(encrypted_message)
                            # message = {"type": "success", "message": f"Group '{group_name}': message from {username}: {message}"}
                            # secure_send_message(member_conn, member_cipher, message)
                    response = {"type": "success", "message": f"Message sent to group {group_name} successfully."}
                else:
                    response = {"type": "fail", "message": "You are not a member of the group or the group does not exist."}
            elif command == "add_group_admin":
                group_name, username, new_admin = content.split(",", 2)
                if (
                    group_name in groups
                    and username in groups[group_name]["admins"]
                    and new_admin in groups[group_name]["members"]
                ):
                    groups[group_name]["admins"].append(new_admin)
                    response = {"type": "success", "message":  "Member '{}' is now an admin of group '{}'.".format(new_admin, group_name)}
                else:
                    response = {"type": "fail", "message":  "You are not an admin or a member of the group or the group or username does not exist."}
            else:
                    response = {"type": "fail_", "message":  "Unsupported command."}

            secure_send_message(conn, cipher_client, response)
        except:
            continue
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