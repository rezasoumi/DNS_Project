import socket
import threading
import json
import hmac
from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

USERS_FILE = "users.json"  # JSON file to store registered users
connected_clients = {}
groups = {}
SERVER_PRIVATE_KEY = RSA.generate(2048)  # Generate a new private key
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.publickey()  # Get the corresponding public key
AES_KEY_PASSWORD = b'ServerPrivateKey'  # Private key for encryption

def load_users():
    try:
        with open(USERS_FILE, "r") as file:
            users = json.load(file)
    except FileNotFoundError:
        users = {}
    return users

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

def secure_send_message(conn, cipher, message):
    hmac_digest = hmac.new(b'', message.encode(), digestmod='sha256').digest()
    data = {
        'hmac': hmac_digest.hex(),
        'message': message
    }
    json_data = json.dumps(data).encode()
    
    conn.send(cipher.encrypt(json_data))

users = load_users()

def handle_client(conn, client_address):
    conn.send(SERVER_PUBLIC_KEY.export_key())
    cipher_server = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)
    client_public_key = RSA.import_key(conn.recv(1024))
    cipher_client = PKCS1_OAEP.new(client_public_key)

    while True:
        decrypted_data = cipher_server.decrypt(conn.recv(1024))
        data = json.loads(decrypted_data.decode())
        received_hmac = bytes.fromhex(data['hmac'])
        received_message = data['message']
        hmac_digest = hmac.new(b'', received_message.encode(), digestmod='sha256').digest()

        if hmac.compare_digest(received_hmac, hmac_digest):
            print("Received from client {}:{}".format(client_address[0], client_address[1]) + " - " + received_message)
        else:
            print('HMAC verification failed!')
            continue

        command, content = received_message.split(":", 1)

        if command == "register":
            username, password = content.split(",")
            if username in users:
                response = "Username already exists. Please choose a different username."
            else:
                encrypted_password = str(encrypt_password(password))
                users[username] = encrypted_password
                save_users(users)
                response = "Registration successful. You can now login."
        elif command == "login":
            username, password = content.split(",")
            encrypted_password = encrypt_password(password)
            if username in users and users[username] == str(encrypted_password):
                response = "Login successful. Welcome, {}!".format(username)
                connected_clients[username] = {
                    "conn": conn,
                    "cipher": cipher_client
                }
            else:
                response = "Invalid username or password. Please try again."
        elif command == "message":
            sender, receiver, message = content.split(",", 2)
            if sender in connected_clients and receiver in connected_clients:
                receiver_conn = connected_clients[receiver]["conn"]
                receiver_cipher = connected_clients[receiver]["cipher"]
                message = f"Message from {sender}: {message}"
                secure_send_message(receiver_conn, receiver_cipher, message)
                response = "Message sent successfully."
            else:
                response = "Sender or receiver is not logged in."
        elif command == "create_group":
            group_name, username = content.split(",")
            if group_name in groups:
                response = "Group name already exists. Please choose a different group name."
            elif username not in users:
                response = "Invalid username. Please log in first."
            else:
                groups[group_name] = {"admin": [username], "members": [username]}
                response = "Group '{}' created successfully.".format(group_name)
        elif command == "send_group_message":
            group_name, username, message = content.split(",", 2)
            if group_name in groups and username in groups[group_name]["members"]:
                for member in groups[group_name]["members"]:
                    if member in connected_clients and member != username:
                        member_conn = connected_clients[member]["conn"]
                        member_cipher = connected_clients[member]["cipher"]
                        message = f"Group '{group_name}': message from {username}: {message}"
                        secure_send_message(member_conn, member_cipher, message)
                response = "Message sent successfully."
            else:
                response = "You are not a member of the group or the group does not exist."
        elif command == "add_group_member":
            group_name, username, new_member = content.split(",", 2)
            if group_name in groups and username in groups[group_name]["admin"] and new_member in users:
                groups[group_name]["members"].append(new_member)
                for member in groups[group_name]["members"]:
                    if member in connected_clients:
                        member_conn = connected_clients[member]["conn"]
                        member_cipher = connected_clients[member]["cipher"]
                        message = f"Group '{group_name}': Member {new_member} added to group"
                        secure_send_message(member_conn, member_cipher, message)
                response = "Member added successfully".format(new_member, group_name)
            else:
                response = "You are not a member of the group or the group or username does not exist."
        elif command == "add_group_admin":
            group_name, username, new_admin = content.split(",", 2)
            if (
                group_name in groups
                and username in groups[group_name]["admin"]
                and new_admin in groups[group_name]["members"]
            ):
                groups[group_name]["admin"].append(new_admin)
                response = "Member '{}' is now an admin of group '{}'.".format(new_admin, group_name)
            else:
                response = "You are not an admin or a member of the group or the group or username does not exist."
        
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