from cryptography.fernet import Fernet
from argparse import ArgumentParser

class Server:
    def __init__(self):
        print("Hello froms server")


class Client:
    def __init__(self):
        print("Hello from client")


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
