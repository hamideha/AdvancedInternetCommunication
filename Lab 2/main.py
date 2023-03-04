from cryptography.fernet import Fernet
from argparse import ArgumentParser
import socket
import sys

GET_MIDTERM_AVG = "GMA"
GET_EXAM_AVG = "GEA"
GET_LAB_1_AVG = "GL1A"
GET_LAB_2_AVG = "GL2A"
GET_LAB_3_AVG = "GL3A"
GET_LAB_4_AVG = "GL4A"
GET_GRADES = "GG"

RECV_BUFFER_SIZE = 1024
FILENAME = "course_grades_2023.csv"


class Server:
    HOSTNAME = "0.0.0.0"
    PORT = 50000
    MAX_CONNECTION_BACKLOG = 10
    MSG_ENCODING = "utf-8"

    def __init__(self):
        self.students = []
        self.GMA = 0
        self.GEA = 0
        self.GL1A = 0
        self.GL2A = 0
        self.GL3A = 0
        self.GL4A = 0

        self.read_csv(FILENAME)
        self.create_listen_socket()
        self.process_connections_forever()

    def read_csv(self, filename):
        with open(filename) as f:
            fields = f.readline()
            headers = fields.strip().split(",")

            lines = f.readlines()
            for line in lines:
                student = {"grades": {}}
                students_props = line.strip().split(",")
                for i in range(len(students_props)):
                    if i < 3:
                        student[headers[i]] = students_props[i]
                    # Add grades to separate nested dict
                    else:
                        student["grades"][headers[i]] = students_props[i]
                self.students.append(student)
            f.close()
        # Print the database
        print("\n\nData read from database:\n")
        print(fields)

        number_of_students = 0

        for line in lines:
            print(line, end="")
            self.GMA += float(line.split(",")[7])
            self.GEA += (
                float(line.split(",")[8])
                + float(line.split(",")[9])
                + float(line.split(",")[10])
                + float(line.split(",")[11])
            ) / 4
            self.GL1A += float(line.split(",")[3])
            self.GL2A += float(line.split(",")[4])
            self.GL3A += float(line.split(",")[5])
            self.GL4A += float(line.split(",")[6])
            number_of_students += 1

        self.GMA /= number_of_students
        self.GEA /= number_of_students
        self.GL1A /= number_of_students
        self.GL2A /= number_of_students
        self.GL3A /= number_of_students
        self.GL4A /= number_of_students

    def read_command(self, command):
        student_id = command.split(" ")[0]
        current_command = command.split(" ")[1]
        self.current_student = next(
            (
                student
                for student in self.students
                if student["ID Number"] == student_id
            ),
            None,
        )
        if not self.current_student:
            print("User not found")
            return "User not found"
        else:
            print(f"Received {current_command} command from client")
            match current_command:
                case "GMA":
                    return f"Midterm Average = {str(self.GMA)}"
                case "GEA":
                    return f"Exam Average = {str(self.GEA)}"
                case "GL1A":
                    return f"Lab 1 Average = {str(self.GL1A)}"
                case "GL2A":
                    return f"Lab 2 Average = {str(self.GL2A)}"
                case "GL3A":
                    return f"Lab 3 Average = {str(self.GL3A)}"
                case "GL4A":
                    return f"Lab 4 Average = {str(self.GL4A)}"
                case "GG":
                    unpacked_dict = ""
                    for key, value in self.current_student["grades"].items():
                        unpacked_dict += f"\n{key} = {value}"
                    return unpacked_dict
                    # return str(self.current_student["grades"])
                case _:
                    return "Unknown Command"

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.PORT))
            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print(f"Listening on port {Server.PORT}...")
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
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        # Print the ip address and port of the client.
        print("-" * 72)
        print(f"Connection received from {address_port[0]} on port {address_port[1]}.")

        while True:
            try:
                recvd_bytes = connection.recv(RECV_BUFFER_SIZE)

                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break

                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

                response_str = self.read_command(recvd_str)
                connection.sendall(self.encrypt_message(response_str))
                print(f"Sent: {response_str}\n")

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

    def encrypt_message(self, message):
        if not self.current_student:
            return message.encode(Server.MSG_ENCODING)
        fernet = Fernet(self.current_student["Key"].encode(Server.MSG_ENCODING))
        return fernet.encrypt(message.encode(Server.MSG_ENCODING))


class Client:
    SERVER_HOSTNAME = socket.gethostname()

    def __init__(self):
        self.student_id = ""
        self.encryption_keys = self.get_encryption_keys(FILENAME)
        self.get_socket()
        self.connect_to_server()
        self.send_console_input_forever()

    def get_encryption_keys(self, filename):
        with open(filename) as f:
            lines = f.readlines()
            return {line.split(",")[1]: line.split(",")[2] for line in lines[1:]}

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
            if not self.student_id:
                self.student_id = input("Student ID: ")
            self.input_text = input("Command: ")
            if self.input_text != "":
                print("Command Entered: ", self.input_text)
                if self.input_text == GET_GRADES:
                    print("Fetching Grades...")
                elif self.input_text == GET_MIDTERM_AVG:
                    print("Fetching Midterm Average...")
                elif self.input_text == GET_EXAM_AVG:
                    print("Fetching Exam 1 Average...")
                elif self.input_text == GET_LAB_1_AVG:
                    print("Fetching Lab 1 Average...")
                elif self.input_text == GET_LAB_2_AVG:
                    print("Fetching Lab 2 Average...")
                elif self.input_text == GET_LAB_3_AVG:
                    print("Fetching Lab 3 Average...")
                elif self.input_text == GET_LAB_4_AVG:
                    print("Fetching Lab 4 Average...")
                else:
                    print("Invalid command")
                    continue
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
            # Send the student id with every request
            msg = self.student_id + " " + self.input_text
            self.socket.sendall(msg.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            recvd_bytes = self.socket.recv(RECV_BUFFER_SIZE)

            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            recvd_msg = self.decrypt_message(recvd_bytes)
            print(f"Received: {recvd_msg}\n")
            if recvd_msg == "User not found":
                self.student_id = ""

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def decrypt_message(self, message):
        key = self.encryption_keys.get(self.student_id)
        if not key:
            return message.decode(Server.MSG_ENCODING)
        fernet = Fernet(key.encode(Server.MSG_ENCODING))
        return fernet.decrypt(message).decode(Server.MSG_ENCODING)


if __name__ == "__main__":
    roles = {"client": Client, "server": Server}
    parser = ArgumentParser()

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
