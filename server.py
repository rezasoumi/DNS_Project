import socket
import threading
import json

USERS_FILE = "users.json"  # JSON file to store registered users
connected_clients = {}
groups = {}

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

users = load_users()

def handle_client(conn, client_address):
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        
        print("Received from client {}:{}".format(client_address[0], client_address[1]) + " - " + data)
        
        command, content = data.split(":", 1)

        if command == "register":
            username, password = content.split(",")
            if username in users:
                response = "Username already exists. Please choose a different username."
            else:
                users[username] = password
                save_users(users)
                response = "Registration successful. You can now login."
        elif command == "login":
            username, password = content.split(",")
            if username in users and users[username] == password:
                response = "Login successful. Welcome, {}!".format(username)
                connected_clients[username] = conn
            else:
                response = "Invalid username or password. Please try again."
        elif command == "message":
            sender, receiver, message = content.split(",", 2)
            if sender in connected_clients and receiver in connected_clients:
                receiver_conn = connected_clients[receiver]
                receiver_conn.send(f"Message from {sender}: {message}".encode())
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
                    if member in connected_clients:
                        member_conn = connected_clients[member]
                        member_conn.send(f"Group '{group_name}': message from {username}: {message}".encode())
                response = "Message sent successfully."
            else:
                response = "You are not a member of the group or the group does not exist."
        elif command == "add_group_member":
            group_name, username, new_member = content.split(",", 2)
            if group_name in groups and username in groups[group_name]["admin"] and new_member in users:
                groups[group_name]["members"].append(new_member)
                for member in groups[group_name]["members"]:
                    if member in connected_clients:
                        member_conn = connected_clients[member]
                        member_conn.send(f"Group '{group_name}': Member {new_member} added to group".encode())
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
                response = "You are not a member of the group or the group or username does not exist."

        conn.send(response.encode())

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