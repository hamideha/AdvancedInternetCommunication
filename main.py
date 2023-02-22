from cryptography.fernet import Fernet
from argparse import ArgumentParser
import socket
import sys

GET_MIDTERM_AVG_CMD  = "GMA"
GET_LAB_1_AVG_CMD    = "GL1A"
GET_LAB_2_AVG_CMD    = "GL2A"
GET_LAB_3_AVG_CMD    = "GL3A"
GET_LAB_4_AVG_CMD    = "GL4A"
GET_EXAM_1_AVG_CMD   = "GE1A"
GET_EXAM_2_AVG_CMD   = "GE2A"
GET_EXAM_3_AVG_CMD   = "GE3A"
GET_EXAM_4_AVG_CMD   = "GE4A"
GET_GRADES_CMD       = "GG"

class Server:
    HOSTNAME = "0.0.0.0"
    PORT = 50000
    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10
    MSG_ENCODING = "utf-8"

    def __init__(self):
        self.read_csv("course_grades_2023.csv")
        self.create_listen_socket()
        self.process_connections_forever()

    def read_csv(self, filename):
        with open(filename) as f:
            data = f.read()
        print("Data read from database:\n")
        print(data)

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.PORT))
            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening on port {}...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        # Print the ip address and port of the client.
        print("-" * 72)
        print("Connection received from {} on port {}.".format(address_port[0], address_port[1]))

        while True:
            try:
                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)
            
                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break
                
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                print("Received: ", recvd_str)
                
                connection.sendall(recvd_bytes)
                print("Sent: ", recvd_str)

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break


    
class Client:
    SERVER_HOSTNAME = socket.gethostname()
    RECV_BUFFER_SIZE = 1024

    def __init__(self):
        self.get_socket()
        self.connect_to_server()
        self.send_console_input_forever()

    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def get_console_input(self):
        while True:
            self.input_text = input("Input: ")
            if self.input_text != "":
                break
    
    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                self.connection_send()
                self.connection_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit(1)
                
    def connection_send(self):
        try:
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)

            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            recvd_msg = recvd_bytes.decode(Server.MSG_ENCODING)
            print("Received: ", recvd_msg)

        except Exception as msg:
            print(msg)
            sys.exit(1)

   

if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='server or client role',
                        required=True,
                        type=str)

    args = parser.parse_args()
    roles[args.role]()
