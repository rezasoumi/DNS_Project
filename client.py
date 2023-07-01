import socket
import threading
import hmac
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from Crypto.Util.Padding import pad, unpad
import hashlib
import sys
import time
import random

def generate_pub_prv_key(user, rsa_key_size):
    global CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY
    
    CLIENT_PRIVATE_KEY = RSA.generate(rsa_key_size)
    CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.publickey()

    password = input("Enter private key password: ")

    hashed_password = hashlib.sha256(password.encode()).digest()

    ciphered_private_key = CLIENT_PRIVATE_KEY.export_key(passphrase=hashed_password, pkcs=8, protection="scryptAndAES128-CBC")

    with open(f"{user}_private_rsa.pem", "wb") as file:
       file.write(ciphered_private_key)

    with open(f"{user}_public_rsa.pem", "wb") as file:
       file.write(CLIENT_PUBLIC_KEY.export_key())

def load_pub_prv_key(user):
    global CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY, cipher_client_public, signer

    password = input("Enter private key password: ")
    hashed_password = hashlib.sha256(password.encode()).digest()

    print(f"{user}_private_rsa.pem")
    with open(f"{user}_private_rsa.pem", "rb") as file:
        encrypted_data = file.read()

    CLIENT_PRIVATE_KEY = RSA.import_key(encrypted_data, passphrase=hashed_password)
    print(f"{user}_public_rsa.pem")
    with open(f"{user}_public_rsa.pem", "rb") as file:
        public_key = file.read()
        CLIENT_PUBLIC_KEY = RSA.import_key(public_key)

    cipher_client_public = PKCS1_OAEP.new(CLIENT_PUBLIC_KEY)
    signer = PKCS1_v1_5.new(CLIENT_PRIVATE_KEY)
    print("done1")

user_name = ""
# CLIENT_PRIVATE_KEY = RSA.generate(1024)  # Generate a new private key
# CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.publickey()  # Get the corresponding public key
# cipher_client_public = PKCS1_OAEP.new(CLIENT_PUBLIC_KEY)
CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY = None, None
cipher_client_public = None
session_keys = {}
cipher_client = None
archive = {}
private_DH_keys = {}
CERT = "client"
signer = None
verifier = {}
cipher_end2end_public_key = {}
tcp_seq_num = {}
groups = {}

# generate_pub_prv_key(sys.argv[1], 2048)
load_pub_prv_key(sys.argv[1])

def run_session_key_agreement_protocol(client_socket, cipher_server, receiver , sender):
    data = {
        'command': 'connect2',
        'message': receiver + ',' + sender
    }
    secure_send_message(client_socket, cipher_server, data)

def secure_send_message(conn, cipher, data):
    data['tcp_seq_num'] = tcp_seq_num["server"]["send"]
    tcp_seq_num["server"]["send"] += 1
    if tcp_seq_num["server"]["send"] > 100000:
        tcp_seq_num["server"]["send"] = 0
    json_data = json.dumps(data).encode()
    conn.send(cipher.encrypt(json_data))
    sign = signer.sign(SHA256.new(json_data))
    time.sleep(2)
    conn.send(sign)

def save_message_to_archive(packet, username):
    global cipher_client_public
    json_data = json.dumps(packet).encode()
    if username not in archive.keys():
        archive[username] = [cipher_client_public.encrypt(json_data)]
    else:
        archive[username].append(cipher_client_public.encrypt(json_data))

def read_messages_from_archive(user):
    if user not in archive.keys():
        return "No history woth this user"
    messages = [json.loads(cipher_client.decrypt(cipher).decode()) for cipher in archive[user]]
    return messages

def regenrate_rsa_pair_key(conn, cipher, user):
    global signer, archive, cipher_client, CLIENT_PRIVATE_KEY, cipher_client_public
    change_key_req = {
        'command': "change_key_req",
        'message': user,
        'cert': "client"
    }
    secure_send_message(conn, cipher, change_key_req)
    data = {key: [json.loads(cipher_client.decrypt(cipher_text).decode()) for cipher_text in value] for key, value in archive.items()}
    # data = {key: [cipher_client.decrypt(cipher_text) for cipher_text in value] for key, value in archive.items()}
    # generate_pub_prv_key(user, 5000)
    
    load_pub_prv_key("reza")
    data = {key: [cipher_client_public.encrypt(json.dumps(json_data).encode()) for json_data in value] for key, value in archive.items()}
    # archive = {key: [cipher_client_public.encrypt(json_data) for json_data in value] for key, value in archive.items()}
    time.sleep(0.2)
    conn.send(CLIENT_PUBLIC_KEY.export_key())
    cipher_client = PKCS1_OAEP.new(CLIENT_PRIVATE_KEY)
    signer = PKCS1_v1_5.new(CLIENT_PRIVATE_KEY)
    return 

def exchange_public_key(conn):
    server_public_key = RSA.import_key(conn.recv(65536))
    certificate_server = json.loads(conn.recv(65536).decode())
    if certificate_server["id"] == "server" and server_public_key == RSA.import_key(certificate_server["public_key"].encode()):
        print("Server public key certificate is ok.")
    else:
        print("Server public key certificate was not ok.")
        return None, None, None
    tcp_seq_num["server"] = {}
    tcp_seq_num["server"]["send"] = certificate_server['tcp_seq_num']
    cipher_server = PKCS1_OAEP.new(server_public_key)
    
    conn.send(CLIENT_PUBLIC_KEY.export_key())
    
    tcp_seq_num["server"]["receive"] = random.randint(0, 100000)
    client_certificate = {
        'id': "client",
        'public_key': CLIENT_PUBLIC_KEY.export_key().decode(),
        'tcp_seq_num': tcp_seq_num["server"]["receive"]
    }
    client_certificate = json.dumps(client_certificate).encode()
    conn.send(client_certificate)
    cipher_client = PKCS1_OAEP.new(CLIENT_PRIVATE_KEY)

    return cipher_client, cipher_server, server_public_key

def client_program(user):
    host = socket.gethostname()  # as both code is running on same pc
    port = 5001  # socket server port number

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
            data, message = None, ""

            if command == "exit":
                client_socket.send("exit".encode())
                break
            elif command == "help":
                print("Commands:\n--online-users\n--register\n--login\n--logout\n--message (sending message to another person)\n--create_group\n--send_group_message\n--add_group_member\n--add_group_admin")
                continue
            elif command == "online-users":
                message = user_name
            elif command == "history-chat":
                print("Enter username or group_name to show history chat:")
                username = input()
                messages = read_messages_from_archive(username)
                hist_chat = ""
                print("messages:", messages)
                print(len(messages))
                for m in messages:
                    if "group_name" in m:
                        hist_chat += f"Group {m['group_name']} - {m['sender']}: " + m['message'] + "\n"
                    else:
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
                if user != username:
                    message = "NoSuchThing" + "," + password
                message = username + "," + password
            elif command == "logout":
                message = user_name
            elif command == "regenerate_rsa_key":
                regenrate_rsa_pair_key(client_socket, cipher_server, user_name)
                continue
            elif command == "connect":
                print("Enter ID of the person you want to communicate with:")
                receiver = input()
                parameters = dh.generate_parameters(generator=2, key_size=512)
                private_key_dh = parameters.generate_private_key()
                private_DH_keys[receiver] = [private_key_dh, parameters]

                public_key_class = private_key_dh.public_key()
                root = parameters.parameter_numbers().p
                generator = parameters.parameter_numbers().g
                public_key_value = public_key_class.public_numbers().y
                cert = CERT
                if receiver not in tcp_seq_num:
                    tcp_seq_num[receiver] = {}
                tcp_seq_num[receiver]["receive"] = random.randint(0, 100000)
                data = {
                    'command': "DH_1",
                    'message': user_name + "," + receiver,
                    'root': root,
                    'generator': generator,
                    'pub_key_dh_sender': public_key_value,
                    'cert': cert,
                    'tcp_num': tcp_seq_num[receiver]["receive"]
                }
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
                # Update: tcp_seq_num[receive]["send"] += 1
                
                #with open("session_key.key", "rb") as file:
                #    session_key = file.read()
                print("Enter recipient:")
                receiver = input()
                data = {
                    'command': command,
                    'message': f"{user_name},{receiver}"
                }
                secure_send_message(client_socket, cipher_server, data)
                print("Enter message:")
                message = input()
                json_message = {
                    "message": message,
                    "sender": user_name,
                    "tcp_seq_num": tcp_seq_num[receiver]["send"], # update later
                    "mac": 1 # update later
                }
                tcp_seq_num[receiver]["send"] += 1
                if tcp_seq_num[receiver]["send"] > 100000:
                    tcp_seq_num[receiver]["send"] = 0
                save_message_to_archive(json_message, receiver)
                json_bytes = json.dumps(json_message).encode('utf-8')
                session_key = session_keys[receiver]
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'session_key',
                ).derive(session_key)
                cipher = AES.new(derived_key, AES.MODE_ECB)
                encrypted_data = cipher.encrypt(pad(json_bytes, AES.block_size))
                client_socket.send(encrypted_data)
                sign = signer.sign(SHA256.new(json_bytes))
                client_socket.send(sign)
                continue
            elif command == "create_group":
                print("Enter group name:")
                group_name = input()
                data = {
                    'command': "create_group",
                    'message': user_name + "," + group_name
                }
            elif command == "add_group_member":
                print("Enter group name:")
                group_name = input()
                print("Enter username of member to add:")
                new_member = input()
                if group_name not in groups:
                    print("Invalid group name.")
                    continue
                parameters = groups[group_name]['parameters']
                dummy_dh_private_key = parameters.generate_private_key()
                dummy_dh_public_key = dummy_dh_private_key.public_key()
                data = {
                    'command': "add_group_member",
                    'message': group_name + "," + user_name + "," + new_member,
                    'server_dh_pub_key_value': dummy_dh_public_key.public_numbers().y
                }
                print("add_group_member command sent.")
            elif command == "delete_group_member":
                print("Enter group name:")
                group_name = input()
                print("Enter username of member to delete:")
                remove_member = input()
                if group_name not in groups:
                    print("Invalid group name.")
                    continue
                parameters = groups[group_name]['parameters']
                dummy_dh_private_key = parameters.generate_private_key()
                dummy_dh_public_key = dummy_dh_private_key.public_key()
                data = {
                    'command': "delete_group_member",
                    'message': group_name + "," + user_name + "," + remove_member,
                    'server_dh_pub_key_value': dummy_dh_public_key.public_numbers().y
                }
                print("delete_group_member command sent.")
            elif command == "send_group_message":
                print("Enter group name:")
                group_name = input()
                print("Enter message:")
                message = input()
                data = {
                    'command': command,
                    'message': f"{user_name},{group_name}"
                }
                secure_send_message(client_socket, cipher_server, data)
                session_key = session_keys[group_name]
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'session_key',
                ).derive(session_key)
                cipher = AES.new(derived_key, AES.MODE_ECB)
                json_message = {
                    "message": message,
                    "sender": user_name,
                    "tcp_seq_num": tcp_seq_num[group_name],
                    "mac": 1 # update later
                }
                print(json_message)
                save_message_to_archive({'message': message, 'sender': user_name, 'group_name': group_name}, group_name)
                tcp_seq_num[group_name] += 1
                json_bytes = json.dumps(json_message).encode('utf-8')
                encrypted_data = cipher.encrypt(pad(json_bytes, AES.block_size))
                client_socket.send(encrypted_data)
                continue
            elif command == "add_group_admin":
                print("Enter group name:")
                group_name = input()
                print("Enter username of member to promote as admin:")
                new_admin = input()
                data = {
                    'command': "add_group_admin",
                    'message': "{},{},{}".format(group_name, user_name, new_admin),
                }
            else:
                print("Invalid command. Please try again.")
                continue
            
            if data is None:
                data = {
                    'command': command,
                    'message': message
                }
            secure_send_message(client_socket, cipher_server, data)

            if message.lower() == 'exit':
                break

    def receive_message():
        while True:
            recieved_data = client_socket.recv(65536)
            try:
                if json.loads(recieved_data.decode()) == dict:
                    data = json.loads(recieved_data.decode())
            except:
                decrypted_data = cipher_client.decrypt(recieved_data)
                data = json.loads(decrypted_data.decode())
                print("Encrypt connection")
            
            print(data)

            if data['tcp_seq_num'] == tcp_seq_num["server"]["receive"]:
                print("The message is New.")
                tcp_seq_num["server"]["receive"] += 1
                if tcp_seq_num["server"]["receive"] > 100000:
                    tcp_seq_num["server"]["receive"] = 0
            else:
                print("The message is not New.")
            received_hmac = bytes.fromhex(data['hmac'])
            received_type = data['type']
            hmac_digest = hmac.new(b'', received_type.encode(), digestmod='sha256').digest()

            if hmac.compare_digest(received_hmac, hmac_digest):
                if received_type == "success" or received_type == "failure":
                    print('Received message:', data['message'])
                elif received_type == "end2end":
                    sender = data["sender"]
                    session_key = session_keys[sender]
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'session_key',
                    ).derive(session_key)
                    cipher = AES.new(derived_key, AES.MODE_ECB)
                    decrypted_data = unpad(cipher.decrypt(client_socket.recv(65536)), AES.block_size)
                    decrypted_json = json.loads(decrypted_data.decode('utf-8'))
                    print(decrypted_json)
                    save_message_to_archive(decrypted_json, sender)
                    time.sleep(0.5)
                    rcv_sign = client_socket.recv(65536)
                    is_valid = verifier[sender].verify(SHA256.new(decrypted_data), rcv_sign)
                    if is_valid:
                        print("Signature is valid. The message was signed by Alice.")
                    else:
                        print("Signature is invalid. The message may have been tampered with or not signed by Alice.")
                    if decrypted_json['tcp_seq_num'] == tcp_seq_num[sender]["receive"]:
                        print("The message is New.")
                        tcp_seq_num[sender]["receive"] += 1
                        if tcp_seq_num[sender]["receive"] > 100000:
                            tcp_seq_num[sender]["receive"] = 0
                    else:
                        print("The message is not New.")
                    # Update:
                    # if decrypted_json["tcp_seq_num"] == tcp_seq_num[sender]["receive"]:
                        # Valid Message
                    print(f"Received message from {sender}:", decrypted_json['message'])
                elif received_type == "send_group_message":
                    sender, group_name = data['sender'], data['message']
                    session_key = session_keys[group_name]
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'session_key',
                    ).derive(session_key)
                    cipher = AES.new(derived_key, AES.MODE_ECB)
                    decrypted_data = unpad(cipher.decrypt(client_socket.recv(65536)), AES.block_size)
                    decrypted_json = json.loads(decrypted_data.decode('utf-8'))
                    print(decrypted_json)
                    print(tcp_seq_num[group_name])
                    if tcp_seq_num[group_name] == decrypted_json['tcp_seq_num']:
                        tcp_seq_num[group_name] += 1
                        print(f"Group {group_name} - {sender}:", decrypted_json['message'])
                        data = {
                            'message': decrypted_json['message'],
                            'sender': sender,
                            'group_name': group_name
                        }
                        save_message_to_archive(data, group_name)
                    else:
                        print(f"Attacker tried to send old message to group {group_name}.")
                elif received_type == "create_group":
                    pn = dh.DHParameterNumbers(data['root'], data['generator'])
                    parameters = pn.parameters()
                    my_dh_private_key = parameters.generate_private_key()
                    dh_public_key = my_dh_private_key.public_key()
                    groups[data['group_name']] = {"parameters": parameters, "prv_dh_key": my_dh_private_key, "pub_dh_key": dh_public_key, "messages": []}
                    print(data['message'])
                elif received_type == "add_to_group":
                    pn = dh.DHParameterNumbers(data['root'], data['generator'])
                    parameters = pn.parameters()
                    my_dh_private_key = parameters.generate_private_key()
                    dh_public_key = my_dh_private_key.public_key()
                    print("added?")
                    groups[data['group_name']] = {"parameters": parameters, "prv_dh_key": my_dh_private_key, "pub_dh_key": dh_public_key, "messages": []}
                    print(f"you added to group {data['group_name']}.")
                elif received_type == "delete_from_group":
                    print(f"You were kicked out of the group {data['message']} by {data['admin']}")
                elif received_type == "circular_DH":
                    print(data)
                    group_name = data['group_name']
                    public_numbers = dh.DHPublicNumbers(data['Y'], parameters.parameter_numbers())
                    public_key = public_numbers.public_key()
                    parameters = groups[group_name]['parameters']
                    private_key = groups[group_name]['prv_dh_key']
                    session_key_incomplete = private_key.exchange(public_key)
                    print(1)
                    new_Y = dh.DHPublicNumbers(int.from_bytes(session_key_incomplete, byteorder='big'), parameters.parameter_numbers()).public_key().public_numbers().y
                    print("circular_DH")
                    if data['admin'] != user_name:
                        secure_send_message(client_socket, cipher_server, {'command': 'dummy', 'message': 'pass it'})
                    print(2)
                    data_out = {
                        'command': "circular_DH",
                        'message': 'nothing to say',
                        'Y': new_Y
                    }
                    time.sleep(1)
                    secure_send_message(client_socket, cipher_server, data_out)
                    print("circular DH2")
                    if data['admin'] != user_name:
                        sign = signer.sign(SHA256.new(json.dumps(data_out).encode()))
                        time.sleep(1)
                        client_socket.send(sign)
                    print("circular_DH3")
                elif received_type == "end_circular_DH":
                    print("here")
                    group_name = data['group_name']
                    parameters = groups[group_name]['parameters']
                    public_numbers = dh.DHPublicNumbers(data['Y'], parameters.parameter_numbers())
                    others_public_keys = public_numbers.public_key()
                    private_key = groups[group_name]['prv_dh_key']
                    session_key = private_key.exchange(others_public_keys)
                    groups[group_name]['session_key'] = session_key
                    session_keys[group_name] = session_key
                    tcp_seq_num[group_name] = data['tcp_seq_num_group']
                    print(f"seq group num for {user_name}: ", tcp_seq_num[group_name])
                    print(int.from_bytes(session_key, byteorder='big'))
                    print("session key updated.")
                elif received_type == "DH_2":
                    print("here")
                    sender = data["sender"]
                    data = json.loads(cipher_client.decrypt(client_socket.recv(65536)).decode())
                    
                    # todo check mac and cert
                    dh_private_key, parameters = private_DH_keys[sender]
                    public_numbers = dh.DHPublicNumbers(data['pub_key_dh'], parameters.parameter_numbers())
                    reconstructed_public_key = public_numbers.public_key()
                    public_numbers = dh.DHPublicNumbers(data['pub_key_dh'], parameters.parameter_numbers())
                    reconstructed_public_key = public_numbers.public_key()
                    print("here2")
                    session_key = dh_private_key.exchange(reconstructed_public_key)
                    session_keys[sender] = session_key
                    print(session_key)
                    tcp_seq_num[sender]["send"] = data['tcp_num']

                    sender_public_key = RSA.import_key(client_socket.recv(65536))
                    verifier[sender] = PKCS1_v1_5.new(sender_public_key)
                    cipher = PKCS1_OAEP.new(sender_public_key)
                    cipher_end2end_public_key[sender] = cipher
                    print(f"DH key agreement with {sender} is established.")
                elif received_type == "DH_1":
                    pn = dh.DHParameterNumbers(data['root'], data['generator'])
                    parameters = pn.parameters()
                    my_dh_private_key = parameters.generate_private_key()
                    dh_public_key = my_dh_private_key.public_key()
                    public_numbers = dh.DHPublicNumbers(data['pub_key_dh_sender'], parameters.parameter_numbers())
                    reconstructed_public_key = public_numbers.public_key()
                    session_key = my_dh_private_key.exchange(reconstructed_public_key)
                    sender = data['message'].split(",")[0]
                    session_keys[sender] = session_key
                    if sender not in tcp_seq_num:
                        tcp_seq_num[sender] = {}
                    tcp_seq_num[sender]["send"] = data['tcp_num']
                    tcp_seq_num[sender]["receive"] = random.randint(0, 100000)

                    # sender_public_key = RSA.import_key(data["pub_key_RSA_sender"].encode())
                    sender_public_key = RSA.import_key(client_socket.recv(65536))
                    verifier[sender] = PKCS1_v1_5.new(sender_public_key)

                    cipher = PKCS1_OAEP.new(sender_public_key)
                    cipher_end2end_public_key[sender] = cipher
                    
                    data = {
                        'command': "DH_2",
                        'message': f"{user_name},{sender}"
                    }
                    secure_send_message(client_socket, cipher_server, data)
                    cert = CERT
                    json_message = {
                        "cert": cert,
                        "pub_key_dh": dh_public_key.public_numbers().y,
                        "tcp_num": tcp_seq_num[sender]["receive"],
                        "mac": 1 # update later encrypt sth with private key and send
                    }
                    json_bytes = json.dumps(json_message).encode('utf-8')
                    client_socket.send(cipher.encrypt(json_bytes))
                else:
                    print("kh", data)
            else:
                print('HMAC verification failed!')

    send_thread = threading.Thread(target=send_message)
    receive_thread = threading.Thread(target=receive_message)

    send_thread.start()
    receive_thread.start()

if __name__ == '__main__':
    arguments = sys.argv
    client_program(arguments[1])