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

GMA = 0
GEA = 0
GL1A = 0
GL2A = 0
GL3A = 0
GL4A = 0

# Client needs access to encryption keys so we just hardcode them 🤷🏼‍♂️
ENCRYPTION_KEYS = {
    "1803933": "M7E8erO15CIh902P8DQsHxKbOADTgEPGHdiY0MplTuY=",
    "1884159": "PWMKkdXW4VJ3pXBpr9UwjefmlIxYwPzk11Aw9TQ2wZQ=",
    "1853847": "UVpoR9emIZDrpQ6pCLYopzE2Qm8bCrVyGEzdOOo2wXw=",
    "1810192": "bHdhydsHzwKdb0RF4wG72yGm2a2L-CNzDl7vaWOu9KA=",
    "1891352": "iHsXoe_5Fle-PHGtgZUCs5ariPZT-LNCUYpixMC3NxI=",
    "1811313": "IR_IQPnIM1TI8h4USnBLuUtC72cQ-u4Fwvlu3q5npA0=",
    "1804841": "kE8FpmTv8d8sRPIswQjCMaqunLUGoRNW6OrYU9JWZ4w=",
    "1881925": "_B__AgO34W7urog-thBu7mRKj3AY46D8L26yedUwf0I=",
    "1877711": "dLOM7DyrEnUsW-Q7OM6LXxZsbCFhjmyhsVT3P7oADqk=",
    "1830894": "aM4bOtearz2GpURUxYKW23t_DlljFLzbfgWS-IRMB3U=",
    "1855191": "-IieSn1zKJ8P3XOjyAlRcD2KbeFl_BnQjHyCE7-356w=",
    "1821012": "Lt5wWqTM1q9gNAgME4T5-5oVptAstg9llB4A_iNAYMY=",
    "1844339": "M6glRgMP5Y8CZIs-MbyFvev5VKW-zbWyUMMt44QCzG4=",
    "1898468": "SS0XtthxP64E-z4oB1IsdrzJwu1PUq6hgFqP_u435AA=",
    "1883633": "0L_o75AEsOay_ggDJtOFWkgRpvFvM0snlDm9gep786I=",
    "1808742": "9BXraBysqT7QZLBjegET0e52WklQ7BBYWXvv8xpbvr8=",
    "1863450": "M0PgiJutAM_L9jvyfrGDWnbfJOXmhYt_skL0S88ngkU=",
    "1830190": "v-5GfMaI2ozfmef5BNO5hI-fEGwtKjuI1XcuTDh-wsg=",
    "1835544": "LI14DbKGBfJExlwLodr6fkV4Pv4eABWkEhzArPbPSR8=",
    "1820930": "zoTviAO0EACFC4rFereJuc0A-99Xf_uOdq3GiqUpoeU="
}


class Server:
    HOSTNAME = "0.0.0.0"
    PORT = 50000
    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10
    MSG_ENCODING = "utf-8"

    def __init__(self):
        self.students = []
        self.read_csv("course_grades_2023.csv")
        self.create_listen_socket()
        self.process_connections_forever()

    def read_csv(self, filename):
        global GMA
        global GEA
        global GL1A
        global GL2A
        global GL3A
        global GL4A

        with open(filename) as f:
            fields = f.readline()
            headers = fields.strip().split(',')

            lines = f.readlines()
            for line in lines:
                student = {"grades": {}}
                students_props = line.strip().split(',')
                for i in range(len(students_props)):
                    if i < 3:
                        student[headers[i]] = students_props[i]
                    # Add grades to separate nested dict
                    else:
                        student["grades"][headers[i]] = students_props[i]
                self.students.append(student)
            f.close()
        # Print the database
        print(self.students)
        print("\n\nData read from database:\n")
        print(fields)

        number_of_students = 0

        for line in lines:
            print(line, end='')
            GMA += float(line.split(",")[7])
            GEA += (float(line.split(",")[8]) + float(line.split(",")[9]) +
                    float(line.split(",")[10]) + float(line.split(",")[11]))/4
            GL1A += float(line.split(",")[3])
            GL2A += float(line.split(",")[4])
            GL3A += float(line.split(",")[5])
            GL4A += float(line.split(",")[6])
            number_of_students += 1

        GMA /= number_of_students
        GEA /= number_of_students
        GL1A /= number_of_students
        GL2A /= number_of_students
        GL3A /= number_of_students
        GL4A /= number_of_students

    def read_command(self, command):
        student_id = command.split(" ")[0]
        current_command = command.split(" ")[1]
        self.current_student = next(
            (student for student in self.students if student['ID Number'] == student_id), None)
        if not self.current_student:
            print("User not found")
            return "User not found"
        else:
            print("User found")
            # TODO: Handle different commands

            match current_command:
                case "GMA":
                    return str(GMA)
                case "GEA":
                    return str(GEA)
                case "GL1A":
                    return str(GL1A)
                case "GL2A":
                    return str(GL2A)
                case "GL3A":
                    return str(GL3A)
                case "GL4A":
                    return str(GL4A)
                case "GG":
                    return str(self.current_student["grades"])
                case _:
                    return ("some error")

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
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        # Print the ip address and port of the client.
        print("-" * 72)
        print(
            f"Connection received from {address_port[0]} on port {address_port[1]}.")

        while True:
            try:
                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)

                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break

                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                print("Received: ", recvd_str)

                response_str = self.read_command(recvd_str)
                connection.sendall(self.encrypt_message(response_str))
                print("Sent: ", response_str)

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

    def encrypt_message(self, message):
        if not self.current_student:
            return message.encode(Server.MSG_ENCODING)
        fernet = Fernet(
            self.current_student["Key"].encode(Server.MSG_ENCODING))
        return fernet.encrypt(message.encode(Server.MSG_ENCODING))


class Client:
    SERVER_HOSTNAME = socket.gethostname()
    RECV_BUFFER_SIZE = 1024

    def __init__(self):
        self.student_id = ""
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
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)

            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            recvd_msg = self.decrypt_message(recvd_bytes)
            print("Received: ", recvd_msg)
            if (recvd_msg == "User not found"):
                self.student_id = ""

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def decrypt_message(self, message):
        key = ENCRYPTION_KEYS.get(self.student_id)
        if not key:
            return message.decode(Server.MSG_ENCODING)
        fernet = Fernet(key.encode(Server.MSG_ENCODING))
        return fernet.decrypt(message).decode(Server.MSG_ENCODING)


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
