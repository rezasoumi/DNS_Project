import socket
import threading
import hmac
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

user_name = ""
CLIENT_PRIVATE_KEY = RSA.generate(2048)  # Generate a new private key
CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.publickey()  # Get the corresponding public key
cipher_client_public = PKCS1_OAEP.new(CLIENT_PUBLIC_KEY)
session_keys = {}
cipher_client = None
archive = {}

def run_session_key_agreement_protocol(client_socket, cipher_server, receiver , sender):
    command = 'connect2'
    message = receiver + ',' + sender
    secure_send_message(client_socket, cipher_server, command, message)

def secure_send_message(conn, cipher, command, message):
    hmac_digest = hmac.new(b'', command.encode(), digestmod='sha256').digest()
    data = {
        'hmac': hmac_digest.hex(),
        'command': command,
        'message': message
    }
    json_data = json.dumps(data).encode()
    
    conn.send(cipher.encrypt(json_data))

def save_message_to_archive(packet, username):
    global cipher_client_public
    json_data = json.dumps(packet).encode()
    if username not in archive.keys():
        archive[username] = [cipher_client_public.encrypt(json_data)]
    else:
        archive[username].append(cipher_client_public.encrypt(json_data))

def read_messages_from_archive(user):
    messages = [json.loads(cipher_client.decrypt(cipher).decode()) for cipher in archive[user]]
    return messages

def exchange_public_key(conn):
    server_public_key = RSA.import_key(conn.recv(1024))
    certificate_server = json.loads(conn.recv(1024).decode())
    if certificate_server["id"] == "server" and server_public_key == RSA.import_key(certificate_server["public_key"].encode()):
        print("Server public key certificate is ok.")
    else:
        print("Server public key certificate was not ok.")
        return None, None, None
    cipher_server = PKCS1_OAEP.new(server_public_key)
    
    conn.send(CLIENT_PUBLIC_KEY.export_key())
    client_certificate = {
        'id': "client",
        'public_key': CLIENT_PUBLIC_KEY.export_key().decode()
    }
    client_certificate = json.dumps(client_certificate).encode()
    conn.send(client_certificate)
    cipher_client = PKCS1_OAEP.new(CLIENT_PRIVATE_KEY)

    return cipher_client, cipher_server, server_public_key

def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    print("Connected to the server.")
    
    global cipher_client
    cipher_server = None
    while cipher_server == None:
        cipher_client, cipher_server, server_public_key = exchange_public_key(client_socket)

    def send_message():
        global user_name

        print("Enter a message (or 'exit' to quit):")

        while True:
            command = input()

            if command == "exit":
                client_socket.send("exit".encode())
                break
            elif command == "help":
                print("Commands:\n--online-users\n--register\n--login\n--logout\n--message (sending message to another person)\n--create_group\n--send_group_message\n--add_group_member\n--add_group_admin")
                continue
            elif command == "online-users":
                message = user_name
            elif command == "history-chat":
                print("Show history chat with user:")
                username = input()
                messages = read_messages_from_archive(username)
                hist_chat = ""
                print("messages:", messages)
                print("archive:", archive)
                for m in messages:
                    hist_chat += f"history chat with {username}:\n" + m["sender"] + ": " + m["message"]
                print(hist_chat)
                continue
            elif command == "register":
                print("Enter username:")
                username = input()
                print("Enter password:")
                password = input()
                message = username + "," + password
            elif command == "login":
                print("Enter username:")
                username = input()
                user_name = username
                print("Enter password:")
                password = input()
                message = username + "," + password
            elif command == "logout":
                message = user_name
            elif command == "connect":
                print("Enter ID of the person you want to communicate with:")
                receiver = input()
                message = user_name + "," + receiver
            elif command == "message":
                print("Enter recipient:")
                receiver = input()
                if receiver in session_keys.keys():
                    session_key  = session_keys[receiver]
                else:
                    run_session_key_agreement_protocol(client_socket, cipher_server, receiver , user_name)
                print("Enter message:")
                message = input()
                message = f"{user_name},{receiver},{message}"
            elif command == "end2end":
                # Update: session key from sessionkeys[receiver]
                # Update: tcp_seq_num_receive from tcp_seq_num[receiver]["receive"], tcp_seq_num_send from tcp_seq_num[receiver]["send"]
                # Update: tcp_seq_num[receiver]["send"] += 1
                
                with open("session_key.key", "rb") as file:
                    session_key = file.read()
                print("Enter recipient:")
                receiver = input()
                message = f"{user_name},{receiver}"
                secure_send_message(client_socket, cipher_server, command, message)
                print("Enter message:")
                message = input()
                json_message = {
                    "message": message,
                    "sender": user_name,
                    "tcp_seq_num": 1, # update later
                    "mac": 1 # update later
                }
                save_message_to_archive(json_message, receiver)
                json_bytes = json.dumps(json_message).encode('utf-8')
                cipher = AES.new(session_key, AES.MODE_ECB)
                encrypted_data = cipher.encrypt(pad(json_bytes, AES.block_size))
                client_socket.send(encrypted_data)
                continue
            elif command == "create_group":
                print("Enter group name:")
                group_name = input()
                message = "{},{}".format(group_name, user_name)
            elif command == "send_group_message":
                print("Enter group name:")
                group_name = input()
                print("Enter message:")
                message = input()
                message = "{},{},{}".format(group_name, user_name, message)
            elif command == "add_group_member":
                print("Enter group name:")
                group_name = input()
                print("Enter username of member to add:")
                new_member = input()
                message = "{},{},{}".format(group_name, user_name, new_member)
            elif command == "add_group_admin":
                print("Enter group name:")
                group_name = input()
                print("Enter username of member to promote as admin:")
                new_admin = input()
                message = "{},{},{}".format(group_name, user_name, new_admin)
            else:
                print("Invalid command. Please try again.")
                continue
            
            secure_send_message(client_socket, cipher_server, command, message)

            if message.lower() == 'exit':
                break

    def receive_message():
        while True:
            recieved_data = client_socket.recv(1024)
            try:
                if json.loads(recieved_data.decode()) == dict:
                    data = json.loads(recieved_data.decode())
            except:
                decrypted_data = cipher_client.decrypt(recieved_data)
                data = json.loads(decrypted_data.decode())
                print("Encrypt connection")

            received_hmac = bytes.fromhex(data['hmac'])
            received_type = data['type']
            hmac_digest = hmac.new(b'', received_type.encode(), digestmod='sha256').digest()

            if hmac.compare_digest(received_hmac, hmac_digest):
                if received_type == "success" or received_type == "failure":
                    print('Received message:', data['message'])
                elif received_type == "exchange_key1":
                    parameters = data["alpha&Q"]
                    private_key = parameters.generate_private_key()
                    public_key = private_key.public_key()
                    shared_secret = private_key.exchange(data["DH-Param-public-key1"])
                    session_keys[data["sender"]] = shared_secret
                    client_public_key = RSA.import_key(data["public_key"].encode())
                    cipher_client_end2end = PKCS1_OAEP.new(client_public_key)
                    encrypted = cipher_client_end2end.encrypt(public_key)
                    payload = {
                        'command': "exchange_key2",
                        'sender': user_name,
                        'receiver': data["sender"],
                        'DH-Param-private-key1': data["DH-Param-private-key1"],
                        'DH-Param-public-key2-encrypted': encrypted
                    }
                    json_payload = json.dumps(payload).encode()
                    secure_send_message(client_socket, cipher_client, json_payload)
                elif received_type == "exchange_key3":
                    public_key = data['public_key']
                    print(public_key)
                elif received_type == "end2end":
                    sender = data["sender"]
                    with open("session_key.key", "rb") as file:
                        session_key = file.read()
                    cipher = AES.new(session_key, AES.MODE_ECB)
                    decrypted_data = unpad(cipher.decrypt(client_socket.recv(1024)), AES.block_size)
                    decrypted_json = json.loads(decrypted_data.decode('utf-8'))
                    print(decrypted_json)
                    save_message_to_archive(decrypted_json, sender)
                    # Update:
                    # if decrypted_json["tcp_seq_num"] == tcp_seq_num[sender]["receive"]:
                        # Valid Message
                    print(f"Received message from {sender}:", decrypted_json['message'])
            else:
                print('HMAC verification failed!')

    send_thread = threading.Thread(target=send_message)
    receive_thread = threading.Thread(target=receive_message)

    send_thread.start()
    receive_thread.start()

if __name__ == '__main__':
    client_program()