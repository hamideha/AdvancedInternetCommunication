import socket
import argparse
import sys
import threading

CMD_FIELD_LEN = 1
FILENAME_SIZE_FIELD_LEN = 1
FILESIZE_FIELD_LEN = 8
SOCKET_TIMEOUT = 4
MSG_ENCODING = "utf-8"
CMD = {
    "get": b"\x01",
    "put": b"\x02",
    "list": b"\x03",
}


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
    HOSTNAME = "127.0.0.1"
    SERVICE_DISCOVERY_PORT = 30000
    PORT = 30001
    RECV_SIZE = 1024
    BACKLOG = 5

    BROADCAST_CMD = "SERVICE DISCOVERY"
    SERVICE_NAME = "Abdulrahman, Faizan and Khaled's File Sharing Service"

    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"

    def __init__(self):
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
            print(f"Listening on port {Server.PORT} ...")
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
        try:
            while True:
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
            sys.exit(1)
        finally:
            self.socket.close()

    def process_discovery_connections_forever(self):
        while True:
            try:
                recvd_bytes, address = self.discovery_socket.recvfrom(Server.RECV_SIZE)
                recvd_str = recvd_bytes.decode(MSG_ENCODING)

                if Server.BROADCAST_CMD in recvd_str:
                    self.discovery_socket.sendto(
                        Server.SERVICE_NAME.encode(MSG_ENCODING), address
                    )
            except KeyboardInterrupt:
                print()
                sys.exit(1)

    def connection_handler(self, client):
        connection, address = client
        print("-" * 72)
        print(f"Connection received from {address[0]} on port {address[1]}.")

        ################################################################
        # Process a connection and see if the client wants a file that
        # we have.

        # Read the command and see if it is a GET command.
        status, cmd_field = recv_bytes(connection, CMD_FIELD_LEN)
        # If the read fails, give up.
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        # Convert the command to our native byte order.
        cmd = int.from_bytes(cmd_field, byteorder="big")
        # Give up if we don't get a GET command.
        if cmd != CMD["GET"]:
            print("GET command not received. Closing connection ...")
            connection.close()
            return

        # GET command is good. Read the filename size (bytes).
        status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        filename_size_bytes = int.from_bytes(filename_size_field, byteorder="big")
        if not filename_size_bytes:
            print("Connection is closed!")
            connection.close()
            return

        print("Filename size (bytes) = ", filename_size_bytes)

        # Now read and decode the requested filename.
        status, filename_bytes = recv_bytes(connection, filename_size_bytes)
        if not status:
            print("Closing connection ...")
            connection.close()
            return
        if not filename_bytes:
            print("Connection is closed!")
            connection.close()
            return

        filename = filename_bytes.decode(MSG_ENCODING)
        print("Requested filename = ", filename)

        ################################################################
        # See if we can open the requested file. If so, send it.

        # If we can't find the requested file, shutdown the connection
        # and wait for someone else.
        try:
            file = open(filename, "r").read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            connection.close()
            return

        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file.encode(MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder="big")

        # Create the packet to be sent with the header field.
        pkt = file_size_field + file_bytes

        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            print("Sending file: ", filename)
            print("file size field: ", file_size_field.hex(), "\n")
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return
        finally:
            connection.close()
            return


class Client:

    RECV_SIZE = 10

    def __init__(self):
        self.get_socket()
        self.connect_to_server()
        self.get_file()

    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            self.socket.connect((Server.HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_file(self):

        ################################################################
        # Generate a file transfer request to the server

        # Create the packet cmd field.
        cmd_field = CMD["GET"].to_bytes(CMD_FIELD_LEN, byteorder="big")

        # Create the packet filename field.
        filename_field_bytes = Server.REMOTE_FILE_NAME.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(
            FILENAME_SIZE_FIELD_LEN, byteorder="big"
        )

        # Create the packet.
        print("CMD field: ", cmd_field.hex())
        print("Filename_size_field: ", filename_size_field.hex())
        print("Filename field: ", filename_field_bytes.hex())

        pkt = cmd_field + filename_size_field + filename_field_bytes

        # Send the request packet to the server.
        self.socket.sendall(pkt)

        ################################################################
        # Process the file transfer repsonse from the server

        # Read the file size field returned by the server.
        status, file_size_bytes = recv_bytes(self.socket, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")
            self.socket.close()
            return

        print("File size bytes = ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            self.socket.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder="big")
        print("File size = ", file_size)

        # self.socket.settimeout(4)
        status, recvd_bytes_total = recv_bytes(self.socket, file_size)
        if not status:
            print("Closing connection ...")
            self.socket.close()
            return
        # print("recvd_bytes_total = ", recvd_bytes_total)
        # Receive the file itself.
        try:
            # Create a file using the received filename and store the
            # data.
            print(
                f"Received {len(recvd_bytes_total)} bytes. Creating file: {Client.DOWNLOADED_FILE_NAME}"
            )

            with open(Client.DOWNLOADED_FILE_NAME, "w") as f:
                recvd_file = recvd_bytes_total.decode(MSG_ENCODING)
                f.write(recvd_file)
            print(recvd_file)
        except KeyboardInterrupt:
            print()
            sys.exit(1)


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
