import socket
import argparse
import sys
import threading
import json

CMD_FIELD_LEN = 1
NAME_FIELD_LEN = 8
ADDRESS_FIELD_LEN = 8
PORT_FIELD_LEN = 8

# JUST FOR TESTING
CMD = {
    "getdir": b"\x01",
    "makeroom": b"\x02",
    "deleteroom": b"\x03",
    "bye": b"\x04",
}

RECV_SIZE = 1024
MSG_ENCODING = "utf-8"

RX_BIND_ADDRESS = "0.0.0.0"


class Server:
    HOSTNAME = socket.gethostname()
    PORT = 50010
    BACKLOG = 10

    # chat_rooms = [
    #     {"room1": ("192.168.0.108", 5000)},
    #     {"room2": ("192.168.0.108", 5040)},
    #     {"room3": ("192.168.0.108", 5012)},
    # ]

    chat_rooms = [
        {"room1": ("127.0.0.1", 5020)},
        {"room2": ("127.0.0.1", 5040)},
        {"room3": ("127.0.0.1", 5012)},
    ]

    def __init__(self):
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.PORT))
            self.socket.listen(Server.BACKLOG)
            print(
                f"Chat Room Directory Server listening on on port {Server.PORT} ...")
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
        print(
            f"Connection received from {address_port[0]} on port {address_port[1]}.")

        while True:
            cmd = connection.recv(CMD_FIELD_LEN)
            if cmd == CMD["getdir"]:
                connection.sendall(json.dumps(
                    self.chat_rooms).encode(MSG_ENCODING))

            if cmd == CMD["makeroom"]:
                chatroom_name_len = int.from_bytes(
                    connection.recv(NAME_FIELD_LEN), byteorder="big"
                )

                chatroom_name_bytes = connection.recv(chatroom_name_len)
                chatroom_name = chatroom_name_bytes.decode(MSG_ENCODING)

                address_bytes = connection.recv(ADDRESS_FIELD_LEN)
                address = socket.inet_ntoa(address_bytes)

                port_bytes = connection.recv(PORT_FIELD_LEN)
                port = int.from_bytes(port_bytes, byteorder="big")

                if any((address, port) in room.values() for room in self.chat_rooms):
                    print(
                        f"Chat room {chatroom_name} already exists at {address}:{port}."
                    )
                    break
                else:
                    self.chat_rooms[chatroom_name] = (address, port)
                    print(
                        f"Chat room {chatroom_name} created at {address}:{port}.")

            if cmd == CMD["deleteroom"]:
                chatroom_name_len = int.from_bytes(
                    connection.recv(NAME_FIELD_LEN), byteorder="big"
                )

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
                # connection.close()


class Client:
    TTL = 1  # multicast hop count
    TTL_BYTE = TTL.to_bytes(1, byteorder="big")

    def __init__(self):
        self.dir_list = None
        self.client_name = ""
        self.create_socket()
        self.get_console_input()

    def create_socket(self):
        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        while True:
            try:
                self.input_text = input("\nCommand: ")
                if self.input_text != "":
                    print("Command Entered:", self.input_text)
                    if self.input_text == "connect":
                        self.connect_to_server()
                    elif self.input_text == "getdir":
                        self.getdir()
                    elif self.input_text.split()[0] == "name":
                        self.set_name()
                    elif self.input_text.split()[0] == "chat":
                        self.chat()
                    elif self.input_text == "bye":
                        print("Terminating connection. Goodbye!")
                        self.tcp_socket.sendall(CMD["bye"])
                        self.tcp_socket.close()
                        sys.exit()
                    else:
                        print("Invalid command")
                        continue

            except Exception as msg:
                print(msg)
                self.tcp_socket.close()
                self.create_socket()
                continue

    def connect_to_server(self):
        self.create_socket()
        try:
            self.tcp_socket.connect((Server.HOSTNAME, Server.PORT))
            print("Successfully connected to service")
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def getdir(self):
        self.tcp_socket.sendall(CMD["getdir"])

        getdir_bytes = self.tcp_socket.recv(RECV_SIZE)
        getdir_decoded = json.loads(getdir_bytes.decode(MSG_ENCODING))

        self.dir_list = list(getdir_decoded)
        print(json.dumps(getdir_decoded))

    def set_name(self):
        if(len(self.input_text.split()) != 2):
            print("Name cannot be blank")
            return

        self.client_name = self.input_text.split()[1]
        print(f"Name set to {self.client_name}")
        return

    def chat(self):
        if len(self.input_text.split()) != 2:
            print("You must enter a chat room name")
            return
        elif self.client_name == "":
            print("Set a name before entering a chat room")
            return
        else:
            chatroom_name = self.input_text.split()[1]
            chatroom_address = None
            if self.dir_list != None:
                for dict in self.dir_list:
                    if chatroom_name in dict:
                        chatroom_address = dict[chatroom_name]
                        break
            else:
                print(
                    "Directory is empty. Use the getdir command to load available chat rooms.")

            if (chatroom_address == None):
                print("Chat room does not exist")
                return
            else:
                self.chatroom_address = tuple(chatroom_address)
                self.chatroom_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                self.chatroom_socket.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.TTL_BYTE)
                self.chatroom_socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.chatroom_socket.bind(
                    self.chatroom_address)

                self.chatroom_socket.sendto(f"{self.client_name} has joined the chat".encode(
                    MSG_ENCODING), self.chatroom_address)
                
                

    def chat_listener(self):
        pass

    def chat_input(self):
        pass


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
