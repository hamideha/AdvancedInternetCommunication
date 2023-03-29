import socket
import argparse
import sys
import threading
import json

CMD_FIELD_LEN = 1
NAME_FIELD_LEN = 4 
ADDRESS_FIELD_LEN = 4  
PORT_FIELD_LEN = 4  

CMD = {
    "getdir": b"\x01",
    "makeroom": b"\x02",
    "deleteroom": b"\x03",
    "bye": b"\x04",
}

RECV_SIZE = 1024
MSG_ENCODING = "utf-8"


class Server:
    HOSTNAME = socket.gethostname()
    PORT = 50000
    BACKLOG = 10

    chat_rooms = []

    def __init__(self):
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.PORT))
            self.socket.listen(Server.BACKLOG)
            print(f"Chat Room Directory Server listening on on port {Server.PORT} ...")
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                client = self.socket.accept()
                tcp_thread = threading.Thread(
                    target=self.connection_handler, args=(client,)
                )
                tcp_thread.start()
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
            sys.exit(1)
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print(f"Connection received from {address_port[0]} on port {address_port[1]}.")

        while True:
            cmd = connection.recv(CMD_FIELD_LEN)
            if cmd == CMD["getdir"]:
                connection.sendall(json.dumps(self.chat_rooms).encode(MSG_ENCODING))

            if cmd == CMD["makeroom"]:
                chatroom_name_len = int.from_bytes(connection.recv(NAME_FIELD_LEN), byteorder='big')

                chatroom_name_bytes = connection.recv(chatroom_name_len)
                chatroom_name = chatroom_name_bytes.decode(MSG_ENCODING)
                
                address_bytes = connection.recv(ADDRESS_FIELD_LEN)
                address = socket.inet_ntoa(address_bytes)

                port_bytes = connection.recv(PORT_FIELD_LEN)
                port = int.from_bytes(port_bytes, byteorder='big')

                if any((address, port) in room.values() for room in self.chat_rooms):
                    print(f"Chat room {chatroom_name} already exists at {address}:{port}.")
                    break
                else:
                    self.chat_rooms[chatroom_name] = (address, port)
                    print(f"Chat room {chatroom_name} created at {address}:{port}.")

            if cmd == CMD["deleteroom"]:
                chatroom_name_len = int.from_bytes(connection.recv(NAME_FIELD_LEN), byteorder='big')

                chatroom_name_bytes = connection.recv(chatroom_name_len)
                chatroom_name = chatroom_name_bytes.decode(MSG_ENCODING)

                if any(chatroom_name in room.values() for room in self.chat_rooms):
                    print(f"Chat room {chatroom_name} does not exist")
                    break
                else:
                    self.chat_rooms.remove(chatroom_name)
                    print(f"Chat room {chatroom_name} deleted")
            
            if cmd == CMD["bye"]:
                print("Client disconnected.")
                connection.close()

class Client:
    def __init__(self):
        print("Cliiiient")


if __name__ == "__main__":
    roles = {"client": Client, "server": Server}
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-r",
        "--role",
        choices=roles,
        help="server or client role",
        required=True,
        type=str,
    )

    args = parser.parse_args()
    roles[args.role]()
