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

RX_BIND_ADDRESS = "0.0.0.0"


class Server:
    HOSTNAME = socket.gethostname()
    PORT = 50010
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
            print(f"Chat Room Directory Server listening on port {Server.PORT} ...")
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
                    continue
                else:
                    self.chat_rooms.append(
                        {"name": chatroom_name, "address": (address, port)}
                    )
                    print(f"Chat room {chatroom_name} created at {address}:{port}.")

            if cmd == CMD["deleteroom"]:
                chatroom_name_len = int.from_bytes(
                    connection.recv(NAME_FIELD_LEN), byteorder="big"
                )

                chatroom_name_bytes = connection.recv(chatroom_name_len)
                chatroom_name = chatroom_name_bytes.decode(MSG_ENCODING)

                if any(chatroom_name in room.values() for room in self.chat_rooms):
                    self.chat_rooms = [
                        room
                        for room in self.chat_rooms
                        if room.get("name") != chatroom_name
                    ]
                    print(f"Chat room {chatroom_name} deleted")
                else:
                    print(f"Chat room {chatroom_name} does not exist")
                    continue

            if cmd == CMD["bye"]:
                print("Client disconnected.")
                connection.close()
                break
            # else:
            #     print(
            #         """
            #         Invalid Command. Please enter one of the following accepted commands:

            #         """
            #     )
            #     continue


class Client:
    TTL = 1  # multicast hop count
    TTL_BYTE = TTL.to_bytes(1, byteorder="big")

    def __init__(self):
        self.dir_list = None
        self.client_name = ""
        # self.chatroom_address = ()
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
                command = self.input_text.split()[0]
                if command != "":
                    print("Command Entered:", self.input_text)
                    if command == "connect":
                        self.connect_to_server()
                    elif command == "getdir":
                        self.getdir()
                        print(json.dumps(self.dir_list))
                    elif command == "deleteroom":
                        self.delete_room()
                    elif command == "makeroom":
                        self.make_room()
                    elif command == "name":
                        self.set_name()
                    elif command == "chat":
                        self.getdir()
                        self.chat()
                    elif command == "bye":
                        print("Terminating connection. Goodbye!")
                        self.tcp_socket.sendall(CMD["bye"])
                    else:
                        print("Invalid command")
                        continue

            except Exception as msg:
                print(msg)
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

    def delete_room(self):
        if len(self.input_text.split()) < 2:
            print("Name cannot be blank")
            return

        cmd = CMD["deleteroom"]

        name = self.input_text.split()[1]
        name_bytes = name.encode(MSG_ENCODING)

        name_len = len(name).to_bytes(NAME_FIELD_LEN, byteorder="big")

        pkt = cmd + name_len + name_bytes

        self.tcp_socket.sendall(pkt)

    def make_room(self):
        if len(self.input_text.split()) < 4:
            print("Name, address, and port must be entered")
            return

        cmd = CMD["makeroom"]

        name = self.input_text.split()[1]
        name_bytes = name.encode(MSG_ENCODING)

        name_len = len(name).to_bytes(NAME_FIELD_LEN, byteorder="big")

        address = self.input_text.split()[2]
        address_bytes = socket.inet_aton(address)

        port = int(self.input_text.split()[3])
        port_bytes = port.to_bytes(PORT_FIELD_LEN, byteorder="big")

        pkt = cmd + name_len + name_bytes + address_bytes + port_bytes

        self.tcp_socket.sendall(pkt)

    def set_name(self):
        if len(self.input_text.split()) < 2:
            print("Name cannot be blank")
            return

        self.client_name = " ".join(self.input_text.split()[1:])
        print(f"Name set to {self.client_name}")
        return

    def get_sockets(self):
        try:
            self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.send_socket.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE
            )

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE
            )
            self.socket.bind((RX_BIND_ADDRESS, self.chatroom_address[1]))

            multicast_group_bytes = socket.inet_aton(self.chatroom_address[0])
            multicast_iface_bytes = socket.inet_aton(RX_BIND_ADDRESS)

            multicast_request = multicast_group_bytes + multicast_iface_bytes

            print(
                "Adding membership (address/interface): ",
                self.chatroom_address[0],
                "/",
                RX_BIND_ADDRESS,
            )
            self.socket.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request
            )
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_messages(self):
        while self.chatting:
            try:
                msg_bytes = self.socket.recv(RECV_SIZE)
                msg_decoded = msg_bytes.decode(MSG_ENCODING)
                print(msg_decoded)
            except KeyboardInterrupt:
                print("You left the chatroom.")
                self.chatting = False
                break
            except:
                sys.exit(1)

    def send_messages(self):
        while self.chatting:
            try:
                msg = input()
                sent_msg = self.client_name + ": " + msg
                sent_msg_encoded = sent_msg.encode(MSG_ENCODING)
                self.send_socket.sendto(sent_msg_encoded, self.chatroom_address)
            except KeyboardInterrupt:
                print("You left the chatroom.")
                self.chatting = False
                break
            except:
                sys.exit(1)

    def chat(self):
        if len(self.input_text.split()) < 2:
            print("You must enter a chat room name")
            return

        if self.client_name == "":
            print("Set a name before entering a chat room")
            return

        chatroom_name = self.input_text.split()[1]
        if self.dir_list != None:
            chatroom = next(
                (item for item in self.dir_list if item["name"] == chatroom_name), None
            )
            if chatroom:
                self.chatroom_address = tuple(chatroom["address"])

        else:
            print(
                "Directory is empty. Use the getdir command to load available chat rooms."
            )

        if self.chatroom_address == None:
            print("Chat room does not exist")
            return
        else:
            try:
                self.get_sockets()
                print("\n", "*" * 25, chatroom_name, "*" * 25)

                self.chatting = True

                receive_thread = threading.Thread(
                    target=self.receive_messages, daemon=True
                )
                receive_thread.start()
                self.send_messages()

                self.send_socket.close()
                self.socket.close()
            except Exception as msg:
                print(msg)
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
