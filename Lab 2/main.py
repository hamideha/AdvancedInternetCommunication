from cryptography.fernet import Fernet
from argparse import ArgumentParser
import socket

class Server:
    def __init__(self):
        
        HOST = 'localhost'
        PORT = 10000

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((HOST, PORT))
        s.listen()

        conn, addr = s.accept()
        print(f"Connected by {addr}")

        with conn:
            while True: 
                while True:
                    data = conn.recv(1024)
                    if not data:
                        conn, addr = s.accept()
                        break
                    conn.sendall(b"test")


    
class Client:
    def __init__(self):

        HOST = 'localhost'
        PORT = 10000 

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        s.sendall(b"Hello, world")
        data = s.recv(1024)

        print(f"Received {data!r}")


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
