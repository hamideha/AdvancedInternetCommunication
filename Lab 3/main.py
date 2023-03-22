import socket
import argparse
import sys
import threading
import os

CMD_FIELD_LEN = 1
FILENAME_SIZE_FIELD_LEN = 1
FILESIZE_FIELD_LEN = 8
SOCKET_TIMEOUT = 2

MSG_ENCODING = "utf-8"
RECV_SIZE = 1024

BROADCAST_CMD = "SERVICE DISCOVERY"
CMD = {
    "get": b"\x01",
    "put": b"\x02",
    "list": b"\x03",
    "bye": b"\x04",
}

FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"


class Server:
    HOSTNAME = "0.0.0.0"
    SERVICE_DISCOVERY_PORT = 30000
    PORT = 30001
    BACKLOG = 5

    SERVICE_NAME = "Abdulrahman, Faizan and Khaled's File Sharing Service"
    DIR = "server"

    def __init__(self):
        os.chdir(Server.DIR)
        print("Directory contents: \n")
        for file in os.listdir():
            print(file)
        print("\n")

        self.create_listen_socket()
        self.create_discovery_socket()

        udp_thread = threading.Thread(target=self.process_discovery_connections_forever)
        udp_thread.start()

        self.get_tcp_connection()

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.PORT))
            self.socket.listen(Server.BACKLOG)
            print(f"Listening for file sharing connections on port {Server.PORT} ...")
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def create_discovery_socket(self):
        try:
            self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.discovery_socket.bind((Server.HOSTNAME, Server.SERVICE_DISCOVERY_PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_tcp_connection(self):
        while True:
            client = self.socket.accept()
            tcp_thread = threading.Thread(
                target=self.process_connections_forever, args=(client,)
            )
            tcp_thread.start()

    def process_connections_forever(self, client):
        connection, address = client

        print("-" * 72)
        print(f"Connection received from {address[0]} on port {address[1]}.")
        try:
            while True:
                self.connection_handler(connection)
        except Exception as msg:
            print(msg)
            connection.close()
            sys.exit(1)
        except KeyboardInterrupt:
            print("Closing client connection ...")
            connection.close()
            sys.exit(1)

    def process_discovery_connections_forever(self):
        print(
            f"Listening for service discovery messages on SDP port {Server.SERVICE_DISCOVERY_PORT}"
        )
        while True:
            try:
                recvd_bytes, address = self.discovery_socket.recvfrom(RECV_SIZE)
                recvd_str = recvd_bytes.decode(MSG_ENCODING)

                if BROADCAST_CMD in recvd_str:
                    self.discovery_socket.sendto(
                        Server.SERVICE_NAME.encode(MSG_ENCODING), address
                    )
            except KeyboardInterrupt:
                print()
                sys.exit(1)

    def connection_handler(self, connection):
        cmd = connection.recv(CMD_FIELD_LEN)
        if cmd == CMD["get"]:
            filename_bytes = connection.recv(RECV_SIZE)
            filename = filename_bytes.decode(MSG_ENCODING)

            try:
                file = open(filename, "rb").read()
            except FileNotFoundError:
                print(FILE_NOT_FOUND_MSG)
                return

            file_size_bytes = len(file)

            file_size_field = file_size_bytes.to_bytes(
                FILESIZE_FIELD_LEN, byteorder="big"
            )

            pkt = file_size_field + file

            connection.sendall(pkt)
            print(f"Sending {filename}")

        if cmd == CMD["put"]:
            filename_len_bytes = connection.recv(FILENAME_SIZE_FIELD_LEN)
            filename_len = int.from_bytes(filename_len_bytes, byteorder="big")

            filename_bytes = connection.recv(filename_len)
            filename = filename_bytes.decode(MSG_ENCODING)

            file_size_bytes = connection.recv(FILESIZE_FIELD_LEN)
            file_size = int.from_bytes(file_size_bytes, byteorder="big")

            byte_recv_count = 0
            recv_bytes = b""

            try:
                while byte_recv_count < file_size:
                    new_bytes = connection.recv(
                        min(RECV_SIZE, file_size - byte_recv_count)
                    )

                    if not new_bytes:
                        return
                    byte_recv_count += len(new_bytes)
                    recv_bytes += new_bytes
                print(f"Received {len(recv_bytes)} bytes")
                try:
                    file = open(filename, "wb+")
                    file.write(recv_bytes)
                    file.close()
                except FileNotFoundError:
                    print(FILE_NOT_FOUND_MSG)
                    file.close()
            except:
                os.remove("./", file)
                sys.exit(1)

        if cmd == CMD["list"]:
            listdir_bytes = str(os.listdir()).encode(MSG_ENCODING)

            connection.sendall(listdir_bytes)
            print("Sending ls...")

        if cmd == CMD["bye"]:
            print("Closing client connection ...")
            connection.close()
            sys.exit(1)


class Client:
    BROADCAST_ADDRESS = "255.255.255.255"
    SERVICE_DISCOVERY_PORT = 30000
    ADDRESS_PORT = (BROADCAST_ADDRESS, SERVICE_DISCOVERY_PORT)

    DIR = "client"

    TOTAL_SCANS = 3

    def __init__(self):
        os.chdir(Client.DIR)
        self.create_broadcast_socket()
        self.create_tcp_socket()
        self.get_console_input()

    def create_broadcast_socket(self):
        try:
            self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.broadcast_socket.settimeout(SOCKET_TIMEOUT)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def create_tcp_socket(self):
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
                    print("Command Entered: ", self.input_text)
                    if self.input_text == "scan":
                        print("Scanning...")
                        self.scan()
                    elif self.input_text.split()[0] == "connect":
                        self.connect_to_server(
                            (
                                self.input_text.split()[1],
                                int(self.input_text.split()[2]),
                            )
                        )
                    elif self.input_text == "llist":
                        print("Local List. Fetching local directory structure:")
                        print(os.listdir())
                    elif self.input_text == "rlist":
                        self.tcp_socket.sendall(CMD["list"])
                        rlist_bytes = self.tcp_socket.recv(RECV_SIZE)
                        rlist = rlist_bytes.decode(MSG_ENCODING)
                        print(rlist)
                    elif self.input_text.split()[0] == "put":
                        print(f"Uploading {self.input_text.split()[1]} to server...")
                        self.put_file(self.input_text.split()[1])
                    elif self.input_text.split()[0] == "get":
                        print(
                            f"Downloading {self.input_text.split()[1]} from server..."
                        )
                        self.get_file(self.input_text.split()[1])
                    elif self.input_text == "bye":
                        print("Terminating connection. Goodbye!")
                        self.tcp_socket.sendall(CMD["bye"])
                        self.tcp_socket.close()
                        self.create_tcp_socket()
                    else:
                        print(
                            """
                            Invalid command. Please input one of the following commands in the specified structure:
                            - 'scan' to scan for available File Sharing Services.
                            - 'connect <IP Address> <Port>' to connect to the server at the specified address.
                            - 'llist' to list the contents of the current client directory.
                            - 'rlist' to list the contents of the current server directory.
                            - 'put <file name>' to upload a file to the server.
                            - 'get <file name>' to download a file from the server.
                            - 'bye' to close the connection.
                            """
                        )
            except Exception as msg:
                print(msg)
                self.tcp_socket.close()
                self.create_tcp_socket()
                continue

    def put_file(self, file_name):
        try:
            file = open(file_name, "rb").read()
        except FileNotFoundError:
            print(FILE_NOT_FOUND_MSG)
            return

        filename_bytes = file_name.encode(MSG_ENCODING)
        filename_len = len(filename_bytes)
        filename_len_bytes = filename_len.to_bytes(
            FILENAME_SIZE_FIELD_LEN, byteorder="big"
        )
        file_size_bytes = len(file)
        file_size = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder="big")

        pkt = CMD["put"] + filename_len_bytes + filename_bytes + file_size + file

        try:
            self.tcp_socket.sendall(pkt)
        except:
            return

    def get_file(self, filename):
        self.tcp_socket.sendall(CMD["get"])
        self.tcp_socket.sendall(filename.encode(MSG_ENCODING))

        file_size_field = self.tcp_socket.recv(FILESIZE_FIELD_LEN)
        file_size = int.from_bytes(file_size_field, byteorder="big")

        byte_recv_count = 0
        rec_bytes = b""

        while byte_recv_count < file_size:
            new_bytes = self.tcp_socket.recv(
                min(RECV_SIZE, file_size - byte_recv_count)
            )
            if not new_bytes:
                break
            byte_recv_count += len(new_bytes)
            rec_bytes += new_bytes

        if byte_recv_count != file_size:
            print(f"Unable to download file {filename}")
        else:
            with open(filename, "wb") as f:
                f.write(rec_bytes)
            print("Download Complete!")
        return

    def scan(self):
        scan_results = []
        try:
            for i in range(Client.TOTAL_SCANS):
                print(f"Sending scan {i}")
                self.broadcast_socket.sendto(
                    BROADCAST_CMD.encode(MSG_ENCODING), Client.ADDRESS_PORT
                )

                while True:
                    try:
                        recvd_bytes, address = self.broadcast_socket.recvfrom(RECV_SIZE)
                        recvd_msg = recvd_bytes.decode(MSG_ENCODING)

                        if (recvd_msg, address) not in scan_results:
                            scan_results.append((recvd_msg, address))

                    except socket.timeout:
                        break
        except KeyboardInterrupt:
            pass

        if scan_results:
            for result in scan_results:
                print(result)
                self.get_console_input()
        else:
            print("No services found.")

    def connect_to_server(self, server_address):
        try:
            self.tcp_socket.connect(server_address)
            print("Successfully connected to service")
        except Exception as msg:
            print(msg)


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
