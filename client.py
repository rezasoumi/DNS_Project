import socket
import threading
import hmac
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

user_name = ""
CLIENT_PRIVATE_KEY = RSA.generate(2048)  # Generate a new private key
CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.publickey()  # Get the corresponding public key

def secure_send_message(conn, cipher, message):
    hmac_digest = hmac.new(b'', message.encode(), digestmod='sha256').digest()
    data = {
        'hmac': hmac_digest.hex(),
        'message': message
    }
    json_data = json.dumps(data).encode()
    
    conn.send(cipher.encrypt(json_data))

def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    print("Connected to the server.")
    
    server_public_key = RSA.import_key(client_socket.recv(1024))
    cipher_server = PKCS1_OAEP.new(server_public_key)
    client_socket.send(CLIENT_PUBLIC_KEY.export_key())
    cipher_client = PKCS1_OAEP.new(CLIENT_PRIVATE_KEY)

    def send_message():
        global user_name

        print("Enter a message (or 'exit' to quit):")

        while True:
            command = input()

            if command == "exit":
                client_socket.send("exit".encode())
                break
            elif command == "help":
                print("Commands:\n--register\n--login\n--message (sending message to another person)\n--create_group\n--send_group_message\n--add_group_member\n--add_group_admin")
                continue
            elif command == "register":
                print("Enter username:")
                username = input()
                print("Enter password:")
                password = input()
                message = "register:" + username + "," + password
            elif command == "login":
                print("Enter username:")
                username = input()
                print("Enter password:")
                password = input()
                message = "login:" + username + "," + password
            elif command == "message":
                print("Enter recipient:")
                receiver = input()
                print("Enter message:")
                message = input()
                content = f"{username},{receiver},{message}"
                message = "message:" + content
            elif command == "create_group":
                print("Enter group name:")
                group_name = input()
                message = "create_group:{},{}".format(group_name, username)
            elif command == "send_group_message":
                print("Enter group name:")
                group_name = input()
                print("Enter message:")
                message = input()
                content = "{},{},{}".format(group_name, username, message)
                message = "send_group_message:" + content
            elif command == "add_group_member":
                print("Enter group name:")
                group_name = input()
                print("Enter username of member to add:")
                new_member = input()
                content = "{},{},{}".format(group_name, username, new_member)
                message = "add_group_member:" + content
            elif command == "add_group_admin":
                print("Enter group name:")
                group_name = input()
                print("Enter username of member to promote as admin:")
                new_admin = input()
                content = "{},{},{}".format(group_name, username, new_admin)
                message = "add_group_admin:" + content
            else:
                print("Invalid command. Please try again.")
                continue
            
            secure_send_message(client_socket, cipher_server, message)

            if message.lower() == 'exit':
                break

    def receive_message():
        while True:
            decrypted_data = cipher_client.decrypt(client_socket.recv(1024))
            data = json.loads(decrypted_data.decode())
            received_hmac = bytes.fromhex(data['hmac'])
            received_message = data['message']
            hmac_digest = hmac.new(b'', received_message.encode(), digestmod='sha256').digest()

            if hmac.compare_digest(received_hmac, hmac_digest):
                print('Received message:', received_message)
            else:
                print('HMAC verification failed!')

    send_thread = threading.Thread(target=send_message)
    receive_thread = threading.Thread(target=receive_message)

    send_thread.start()
    receive_thread.start()

if __name__ == '__main__':
    client_program()