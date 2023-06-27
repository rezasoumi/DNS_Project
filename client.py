import socket
import threading

user_name = ""

def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    print("Connected to the server.")

    def send_message():
        global user_name
        print("Enter a message (or 'exit' to quit):")

        while True:
            command = input()

            if command == "exit":
                client_socket.send("exit".encode())
                break

            if command == "register":
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
            else:
                print("Invalid command. Please try again.")
                continue
            
            client_socket.send(message.encode())

            if message.lower() == 'exit':
                break

    def receive_message():
        while True:
            response = client_socket.recv(1024).decode()
            print("Server: " + response)

    send_thread = threading.Thread(target=send_message)
    receive_thread = threading.Thread(target=receive_message)

    send_thread.start()
    receive_thread.start()

if __name__ == '__main__':
    client_program()