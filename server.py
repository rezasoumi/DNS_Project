import socket
import threading

def handle_client(conn, client_address):
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        
        print("Received from client {}:{}".format(client_address[0], client_address[1]) + " - " + data)
        
        response = "Server received " + data
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