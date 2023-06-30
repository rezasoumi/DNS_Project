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

def generate_pub_prv_key(user):
    global CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY
    
    CLIENT_PRIVATE_KEY = RSA.generate(11000)
    CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.publickey()

    password = input("Enter private key password: ")

    hashed_password = hashlib.sha256(password.encode()).digest()

    ciphered_private_key = CLIENT_PRIVATE_KEY.export_key(passphrase=hashed_password, pkcs=8, protection="scryptAndAES128-CBC")

    with open(f"{user}_encrypted_private_key.pem", "wb") as file:
        file.write(ciphered_private_key)

    with open(f"{user}_public_key.pem", "wb") as file:
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

# enerate_pub_prv_key(sys.argv[1])
load_pub_prv_key(sys.argv[1])

def run_session_key_agreement_protocol(client_socket, cipher_server, receiver , sender):
    data = {
        'command': 'connect2',
        'message': receiver + ',' + sender
    }
    secure_send_message(client_socket, cipher_server, data)

def secure_send_message(conn, cipher, data):
    json_data = json.dumps(data).encode()
    conn.send(cipher.encrypt(json_data))
    sign = signer.sign(SHA256.new(json_data))
    time.sleep(0.5)
    conn.send(sign)

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
    server_public_key = RSA.import_key(conn.recv(65536))
    certificate_server = json.loads(conn.recv(65536).decode())
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

def client_program(user):
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
            data = None

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
                parameters = dh.generate_parameters(generator=2, key_size=512)
                private_key_dh = parameters.generate_private_key()
                private_DH_keys[receiver] = [private_key_dh, parameters]

                public_key_class = private_key_dh.public_key()
                root = parameters.parameter_numbers().p
                generator = parameters.parameter_numbers().g
                public_key_value = public_key_class.public_numbers().y
                cert = CERT
                data = {
                    'command': "DH_1",
                    'message': user_name + "," + receiver,
                    'root': root,
                    'generator': generator,
                    'pub_key_dh_sender': public_key_value,
                    'cert': cert
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
                # Update: tcp_seq_num[receiver]["send"] += 1
                
                #with open("session_key.key", "rb") as file:
                #    session_key = file.read()
                print("Enter recipient:")
                receiver = input()
                session_key = session_keys[receiver]
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
                    "tcp_seq_num": 1, # update later
                    "mac": 1 # update later
                }
                save_message_to_archive(json_message, receiver)
                json_bytes = json.dumps(json_message).encode('utf-8')
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
                    # Update:
                    # if decrypted_json["tcp_seq_num"] == tcp_seq_num[sender]["receive"]:
                        # Valid Message
                    print(f"Received message from {sender}:", decrypted_json['message'])
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