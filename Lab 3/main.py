import socket
import argparse
import sys
import threading
import os

CMD_FIELD_LEN = 1
FILENAME_SIZE_FIELD_LEN = 1
FILESIZE_FIELD_LEN = 8
SOCKET_TIMEOUT = 4

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


def recv_bytes(sock, bytecount_target):
    # Be sure to timeout the socket if we are given the wrong
    # information.
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        byte_recv_count = 0  # total received bytes
        recv_bytes = b""  # complete received message
        while byte_recv_count < bytecount_target:
            # Ask the socket for the remaining byte count.
            new_bytes = sock.recv(bytecount_target - byte_recv_count)
            # If ever the other end closes on us before we are done,
            # give up and return a False status with zero bytes.
            if not new_bytes:
                return (False, b"")
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off the socket timeout if we finish correctly.
        sock.settimeout(None)
        return (True, recv_bytes)
    # If the socket times out, something went wrong. Return a False
    # status.
    except socket.timeout:
        sock.settimeout(None)
        print("recv_bytes: Recv socket timeout!")
        return (False, b"")


class Server:
    HOSTNAME = "0.0.0.0"
    SERVICE_DISCOVERY_PORT = 30000
    PORT = 30001
    BACKLOG = 5

    SERVICE_NAME = "Abdulrahman, Faizan and Khaled's File Sharing Service"
    DIR = "server"

    def __init__(self):
        os.chdir(Server.DIR)
        self.create_listen_socket()
        self.create_discovery_socket()

        udp_thread = threading.Thread(target=self.process_discovery_connections_forever)
        udp_thread.start()

        tcp_thread = threading.Thread(target=self.process_connections_forever)
        tcp_thread.start()

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

    def process_connections_forever(self):
        connection, address = self.socket.accept()

        try:
            print("-" * 72)
            print(f"Connection received from {address[0]} on port {address[1]}.")
            while True:
                self.connection_handler(connection)
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print("Closing client connection ...")
            connection.close()
            sys.exit(1)
        finally:
            self.socket.close()

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
                    new_bytes = connection.recv(RECV_SIZE)

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
            except KeyboardInterrupt:
                os.remove("./", file)
                sys.exit(1)

        if cmd == CMD["rlist"]:
            
            pass

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

    # DIR = "./client" # TODO confirm
    SERVER_ADDRESS = "0.0.0.0"
    SERVER_PORT = 30001

    TOTAL_SCANS = 3

    def __init__(self):
        # os.chdir(Client.DIR) TODO confirm
        self.create_broadcast_socket()
        self.get_console_input()

    def create_broadcast_socket(self):
        try:
            self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.broadcast_socket.settimeout(SOCKET_TIMEOUT)
            self.file_transfer_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        while True:
            self.input_text = input("Command: ")
            if self.input_text != "":
                print("Command Entered: ", self.input_text)
                if self.input_text == "scan":
                    print("Scanning...")
                    self.scan()
                elif self.input_text.split[0] == "connect":
                    self.connect_to_server((self.input_text[1], self.input_text[2]))
                elif (
                    self.input_text == "llist"
                ):  # TODO print local client directory structure
                    print("Local List. Fetching local directory structure:")
                    pass
                elif (
                    self.input_text == "rlist"
                ):  # TODO print server directory structure
                    print()
                    pass
                elif (
                    self.input_text.split()[0] == "put"
                ):  # TODO take filename and send that file to server
                    print()
                    pass
                elif (
                    self.input_text.split()[0] == "get"
                ):  # TODO take filename and fetch from server
                    print()
                    pass
                elif self.input_text == "bye":
                    print("Terminating connection. Goodbye!")
                    self.file_transfer_socket.close()
                else:
                    print(
                        "Invalid command. Please input one of the following commands in the specified structure:"
                    )
                    continue
                break

    def scan(self):
        scan_results = []

        try:
            for i in range(Client.TOTAL_SCANS):
                print(f"Sending broadcast scan {i}")
                self.broadcast_socket.sendto(
                    BROADCAST_CMD.encode(MSG_ENCODING), Client.ADDRESS_PORT
                )

                while True:
                    try:
                        recvd_bytes, address = self.broadcast_socket.recvfrom(RECV_SIZE)
                        recvd_msg = recvd_bytes.decode(MSG_ENCODING)

                        if (recvd_msg, address) not in scan_results:
                            scan_results.append((recvd_msg, address))
                            continue

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
            # tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.file_transfer_socket.connect(server_address)
            # tcp_socket.connect((Server.HOSTNAME, Server.PORT))
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
