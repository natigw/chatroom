import hashlib
import json
import os
import socket
import sys
import threading
import time
import uuid

import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from rsa import PublicKey

from custom_input import CustomInput

fernet = None

# SERVER SCHEMAS:
# 1. Server action [CREATE] = {"action":"create", "room_name":"general", "room_welcome_message":"some message", "room_id":"NFV", "room_owner":"admin", "room_password":"admin123"}
# 2. Server action [DELETE] = REQUEST: {"action":"delete", "room_name":"general"}, RESPONSE: {"code": 200, "message":"deletion success"}
# 3. Server action [JOIN]  =  REQUEST: {"action":"join", "user_id":user_id, "username":username}, RESPONSE: {"code": 200, "message":"join success", "room_welcome_message":"welcome, {username}!"}
# 4. Server action [LIST]  =  REQUEST: {"action":"list_rooms"}, RESPONSE: { "code": 200, "message":"list rooms success", "data":[{"room_name":"general", "room_id":"NFV", "room_owner":"admin"}, {}, {}]}

# ROOM SCHEMAS:
# 1. Room action [SEND_MESSAGE] = REQUEST: {"action":"send_message", "user_id":user_id, "message": "hi guys!"}


# GLOBAL VARIABLES
client_socket: socket
sys_input = CustomInput()
user_id = str(uuid.uuid4())
user_mode: str
admin_username: str = None
current_user: str = None

HOSTNAME = socket.gethostname()
IP_ADDRESS = socket.gethostbyname(HOSTNAME)
PORT = 9999
client: socket
public_partner: PublicKey
public_key_endtoend, private_key_endtoend = rsa.newkeys(1024), rsa.newkeys(1024)


def type_print(message, typing_speed=0.05):
    for char in message:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(typing_speed)
    print()  # For new line after the message


def send_command(command, value):
    data = {"action": "command", "command": command, "value": value}
    send_request_encrypted(json.dumps(data).encode('utf-8'))  # Send message


def send_message(message):
    if message == '': return
    if message[0] == "/":
        command = ""
        value = ""
        try:
            # print(message[1:].split('='))
            command = message[1:].split('=')[0]
            value = message[1:].split('=')[1]
        except:
            pass
        send_command(command, value)
    else:
        data = {"action": "send_message", "message": message}
        send_request_encrypted(json.dumps(data).encode('utf-8'))  # Send message


def clear_last_line():
    # Clear the entire line
    sys.stdout.write('\x1b[2K')
    # Move the cursor back
    sys.stdout.write('\r')
    sys.stdout.flush()


# def on_disconnect():
host: str = ''  # Server's IP

def listen_incoming_messages(callback):
    try:
        while True:
            raw_data = client_socket.recv(1024)
            if not raw_data:
                launch_lobby(False)
                break
            data = receive_encrypted_data(raw_data).decode('utf-8')
            response = json.loads(data)  # response should have a standard json format
            callback(response)
    except ConnectionResetError:
        print("This room is deleted by the owner!")
        # launch_lobby(False)


def create_client_socket(server_port):
    global host
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not host:
        host = input("Enter server IP: ")
    port = server_port
    client_socket.connect((host, port))
    return client_socket

def init_encryption():
    global fernet
    # RECEIVE PUBLIC KEY
    public_key_pem = client_socket.recv(4096)
    public_key = serialization.load_pem_public_key(public_key_pem)
    # GENERATE ENCRYPTION KEY
    key = Fernet.generate_key()
    fernet = Fernet(key)
    # ENCRYPT THE KEY
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # SEND ENCRYPTED KEY
    client_socket.sendall(encrypted_key)


# SERVER ACTIONS
def list_rooms():
    # SEND A LIST ACTION REQUEST: {"action":"list_rooms"}
    os.system('cls')
    body = {"action": "list_rooms"}
    client_socket.sendall(json.dumps(body).encode('utf-8'))
    # GET AN ACTION RESPONSE: { "code": 200, "message":"list rooms success", "data":[{"room_name":"Farid's room", "id":"room's id", "owner":"farid_admin"}, {}, {}]}
    response = json.loads(client_socket.recv(1024).decode('utf-8'))
    # Handle error case here
    if response["code"] != 200: return print(response["message"])
    # Handle success case here
    rooms = response['data']
    print(f"\nAvailable rooms:\n")
    for room in rooms:
        type_print(f"Room: {room['room_name']}", 0.04)
        print(f"This room is {room['room_type']}")
        print(f"Room ID: {room['room_id']}")
        if len(room['users']) == 0:
            print("No users in this room")
        else:
            print("Users in this room: ", end="")
        for i, user in enumerate(room['users']):
            if i == len(room['users']) - 1:
                print(f"{user}")
            else:
                print(f"{user}", end=", ")
        print(f"User count: {room['user_count']}")
        print("---------------------------------------------------------")
    return response['data']

def get_users():
    # SEND A LIST ACTION REQUEST: {"action":"list_users"}
    os.system('cls')
    body = {"action": "list_users"}
    client_socket.sendall(json.dumps(body).encode('utf-8'))
    # GET AN ACTION RESPONSE: { "code": 200,  "message":"list users success", "data":[{"username":"natig", "password":"hash of password"}, {}, {}]}
    response = json.loads(client_socket.recv(1024).decode('utf-8'))
    # Handle error case here
    if response["code"] != 200: return print(response["message"])
    # Handle success case here
    users = response['data']
    return users


def join_public_room(room, admin_data):
    global client_socket
    global fernet
    # Disconnect from the lobby
    client_socket.close()
    # Connect to the room
    client_socket = create_client_socket(room['room_port'])
    print("Connected to the room!")
    init_encryption()
    # ENCRYPTED SESSION START
    public_room_logic(room, admin_data)

def join_private_room(room, admin_data):
    global client_socket
    # Disconnect from the lobby
    client_socket.close()
    # Connect to the room
    client_socket = create_client_socket(room['room_port'])
    print("Connected to the room!")
    init_encryption()
    # ENCRYPTED SESSION START
    private_room_logic(room, admin_data)

def private_room_logic(room, admin_data):
    # Configure user first
    os.system('cls')  # clear the terminal
    room_password = input("Please enter room password: ")
    data = {"action": "unlock", "room_password": room_password}
    send_request_encrypted(json.dumps(data).encode('utf-8'))
    response = json.loads(receive_encrypted_data(client_socket.recv(2048)).decode('utf-8'))
    if response['code'] != 200: return print(response['message'])
    public_room_logic(room, admin_data)


def send_request_encrypted(data):
    encrypted_data = fernet.encrypt(data)
    client_socket.sendall(encrypted_data)

def receive_encrypted_data(data):
    decrypted_data = fernet.decrypt(data)
    return decrypted_data


def public_room_logic(room, admin_data):
    # Configure user first
    os.system('cls')  # clear the terminal
    if admin_data:
        print("Welcome, Admin!")
        print("You are now in the room!")
        username = admin_data
    else:
        username = current_user
        if username in room['users']:
            print(f"You are already in the room! Please join another room or create a new one.")
            time.sleep(1)
            launch_lobby(False)
    data = {"action": "join", "user_id": user_id, "username": username}
    send_request_encrypted(json.dumps(data).encode('utf-8'))
    # client_socket.sendall(json.dumps(data).encode('utf-8'))
    # {"code": 200, "message":"join success", "room_welcome_message":"welcome, {username}!"}
    response = json.loads(receive_encrypted_data(client_socket.recv(8192)).decode('utf-8'))
    if response['code'] != 200:
        print(response['message'])
        time.sleep(1)
        return

    print(response['room_welcome_message'])
    response = json.loads(receive_encrypted_data(client_socket.recv(8192)).decode('utf-8'))
    for message in response['messages']:
        print(f">> {message}")

    # create a handler callback
    def handle_response(response):
        if response["code"] != 200: return print(response["message"])

        if response["action"] == "receive_message":
            # clear last printed line
            clear_last_line()
            # Print the received message
            print(response["message"])
            # Reprint the input prompt
            sys.stdout.write(f">> {sys_input.get_current_input()}")
            sys.stdout.flush()

        elif response["action"] == "leave_room":
            print("You have left the room!")
            # launch_lobby(False)

    # start listening for any response, register handler callback
    listener_thread = threading.Thread(target=listen_incoming_messages, args=(handle_response,))
    listener_thread.start()
    # keep asking for user input continuously
    while True:
        time.sleep(0.1)
        message = sys_input.input("\n>> ")
        send_message_ete(message)


def launch_admin_mode(rooms):
    global admin_username
    if not admin_username:
        admin_username = current_user

    choice = input("Please, pick an action [create/delete/join]:\n")

    if choice == "create":
        # { "action":"create", "room_name":"general", "room_welcome_message":"some message", "room_id":"1", "room_owner":"admin", "room_password":"admin123"}
        room_id = input("Please, input a room id that others will use to join: ")
        while room_id in [room['room_id'] for room in rooms]:
            print("Room id already exists, please choose another one.")
            room_id = input("Please, input a room id that others will use to join: ")
        room_name = input("Please, enter a room name: ")
        room_welcome_message = input("Please, enter a room welcome message: ")
        room_password = input("Please, enter a room password [Leave blank for public rooms]: ")
        room_port = int(input("Please, enter a port for the new room: "))
        room_timeout = int(input("Please, enter a timeout for the room [0 for no timeout]: "))

        data = {"action": "create", "room_id": room_id, "room_name": room_name,
                "room_welcome_message": room_welcome_message, "room_password": room_password, "room_port": room_port,
                "room_owner": admin_username, "room_timeout": room_timeout}
        client_socket.sendall(json.dumps(data).encode('utf-8'))
        room_type = "private" if room_password != "" else "public"
        join_data = {"room_name": room_name, "room_id": room_id, "room_port": room_port, "room_owner": admin_username,
                     "user_count": 0, "room_type": room_type, "users": []}
        join_room(join_data, admin_username)
    elif choice == "delete":
        room_id = input("Please, enter the room id you want to delete: ")
        while room_id not in [room['room_id'] for room in rooms]:
            print("Room id does not exist, please choose another one.")
            room_id = input("Please, enter the room id you want to delete: ")
        while room_id in [room['room_id'] for room in rooms if room['room_owner'] != admin_username]:
            print("You are not the owner of this room, please choose another one.")
            room_id = input("Please, enter the room id you want to delete: ")
        data = {"action": "delete", "room_id": room_id}
        client_socket.sendall(json.dumps(data).encode('utf-8'))
        launch_lobby(False)
    elif choice == "join":
        room_id = input("Please, enter the room id you want to join: ")
        while room_id not in [room['room_id'] for room in rooms]:
            print("Room id does not exist, please choose another one.")
            room_id = input("Please, enter the room id you want to join: ")
        for room in rooms:
            if room["room_id"] == room_id and room["room_owner"] == admin_username:
                join_room(room, admin_username)
                return
        print("You are not the admin of this room!")
        time.sleep(1)
        launch_lobby(False)


def join_room(room, admin_data=None):
    try:
        if room['room_type'] == "public":
            join_public_room(room, admin_data)
        elif room['room_type'] == "private":
            join_private_room(room, admin_data)
    except Exception:
        launch_lobby(False)


def launch_user_mode(rooms):
    while True:
        type_print("\nPlease enter a room id from the list above to join:", 0.04)
        room_id = input()
        for room in rooms:
            if room["room_id"] == room_id:
                join_room(room)
                return
        print("\nNo such room exists\n")


def get_hash(string):
    byte_string = string.encode('utf-8')
    hash_object = hashlib.sha256(byte_string)
    hash_hex = hash_object.hexdigest()  # hexadecimal representation of the hash

    return hash_hex

def client_login():
    global current_user
    users = get_users()
    type_print("Sign in to your NFV account.\n", 0.03)
    while True:
        username = input("Enter your username: ").lower()
        password = sys_input.input("Enter your password: ", mask='*')
        password = get_hash(password)
        user = next((user for user in users if user['username'] == username and user['password'] == password), None)
        if user:
            type_print("\n\n\n *** Login successful! *** \n\n", 0.02)
            current_user = username
            launch_lobby(False)
            break
        else:
            print("\nWrong username or password!\n")


def client_register():
    global current_user
    users = get_users()
    while True:
        username = input("Enter a username: ").lower()
        if username in [user['username'] for user in users]:
            print("Username already taken! Please choose another one.\n")
        else:
            break
    password = sys_input.input("Enter a password: ", mask='*')
    user_data = {
        "username": username,
        "password": get_hash(password),
        "date_joined": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    data = {"action": "add_user", username: user_data}
    client_socket.sendall(json.dumps(data).encode('utf-8'))
    type_print("\n\nUser account has been created successfully!\n", 0.03)
    current_user = username
    launch_lobby(False)


def client_credential_update():
    global current_user
    users = get_users()

    while True:
        username = input("\nEnter your username: ").lower()
        if username not in [user['username'] for user in users]:
            print("This user has not registered!\n")
        else:
            old_password = sys_input.input("Enter the old password: ", mask='*')
            old_password = get_hash(old_password)
            user = next((user for user in users if user['username'] == username and user['password'] == old_password),
                        None)
            if user:
                while True:
                    new_password = sys_input.input("\nSet a new password: ", mask='*')
                    if new_password == old_password:
                        print("The new password cannot be same as the old!\n")
                    else:
                        break
                break
            else:
                print("\nIncorrect password!\n")
    updated_user_data = {
        "username": username,
        "password": get_hash(new_password),
        "date_joined": user['date_joined']  # preserve the original join date
    }
    data = {"action": "add_user", username: updated_user_data}
    client_socket.sendall(json.dumps(data).encode('utf-8'))
    print("\nAccount password has been changed successfully!\n")
    current_user = username
    client_login()


def endtoend():
    global client
    global public_partner
    while True:
        choice = input("Are you Sender(1) or Receiver(2), or to navigate back (exit): ")
        type_print("\nWaiting the receiver to come online...")
        # type_print("But you can still type your message, receiver will see it whenever they connects.")

        if choice == "1":
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((IP_ADDRESS, PORT))
            server.listen(1)
            os.system('cls')
            type_print("\nServer has run successfully!\n", 0.02)
            client, _ = server.accept()

            # Exchange public keys
            client.send(public_key_endtoend.save_pkcs1("PEM"))
            public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))

        elif choice == "2":
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ip = input("Enter Sender's IP address: ")
            port = input("Enter Sender's Port number: ")
            client.connect((ip, port))
            os.system('cls')
            type_print("\nConnection established with Partner!\n", 0.02)
            type_print("   *** End-to-End Encryption ***   \n")

            # Exchange public keys
            public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
            client.send(public_key_endtoend.save_pkcs1("PEM"))

        elif choice == "exit":
            launch_lobby(False)
            return
        else:
            print("Wrong choice!")

def send_message_ete(c):
    while True:
        message = input("\n")
        if message == "/quit":
            c.send("[End of Connection]".encode())
            type_print("\n\n GoodBye! ")
            time.sleep(3)
            os.system('cls')
            type_print("Connection has been ended!")
            return
        c.send(message.encode())
        # c.send(rsa.encrypt(message.encode(), public_partner))

def receive_message_ete(c):
    while True:
        message = c.recv(1024).decode()
        # message = rsa.decrypt(c.recv(1024), private_key).decode()
        if message == "[End of Connection]":
            type_print("\n\n Partner says GoodBye to you! ")
            time.sleep(3)
            os.system('cls')
            type_print("\nConnection has been ended!")
            return
        print(f">> {message}")



def launch_lobby(is_first_time):
    global client_socket
    global user_mode
    global current_user
    if is_first_time:
        type_print("\nWelcome to NFV Messenger!\n\n")
    else:
        client_socket.close()

    # Connect to the server lobby (static port: 3169)
    client_socket = create_client_socket(3169)
    if is_first_time:
        while True:
            type_print("\nTo be able to continue you need an account.", 0.03)
            choice = input("Do you have an account: login (1), register (2), or credential update (3): ")
            if choice == "1":
                client_login()
                break
            elif choice == "2":
                client_register()
                break
            elif choice == "3":
                client_credential_update()
            else:
                print("Invalid input!")

    while True:
        type_print("\nDo you want to send a direct message (1) or to join a room (2): ", 0.02)
        choice = input()
        if choice == "1":
            users = get_users()
            print("NFV Messenger users:\n")
            for user in users:
                type_print(f"User: {user['username']}", 0.01)
                print("------------------------------------------------------------")
            while True:
                type_print("\n\nEnter user you want to send message('exit' to navigate back):", 0.02)
                receiver = input()
                if receiver == "exit":
                    launch_lobby(False)
                    return
                elif receiver == current_user:
                    type_print("\n *** You cannot send a message to yourself! *** ", 0.01)
                elif receiver not in [user['username'] for user in users]:
                    print("User not found!\n")
                else:
                    break
            endtoend()
            threading.Thread(target=send_message_ete, args=(client,)).start()
            threading.Thread(target=receive_message_ete, args=(client,)).start()
            return
        elif choice == "2":
            user_mode = input("You want to continue as [user/admin]: ").lower()
            rooms = list_rooms()
            if user_mode == "admin":
                launch_admin_mode(rooms)
            elif user_mode == "user":
                launch_user_mode(rooms)
            break
        else:
            print("Please input 1 or 2.")


if __name__ == "__main__":
    try:
        launch_lobby(True)
    except KeyboardInterrupt:
        print("\nBye!")
        client_socket.close()
    except Exception as e:
        print(f"Something went very wrong! {e} Shutting down...")
    # signal.signal(signal.SIGINT, sigint_handler)
