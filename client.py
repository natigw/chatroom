import socket
import sys
import time
import threading
import json
import uuid
import os
import msvcrt
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from custom_input import CustomInput

fernet = None

# SERVER SCHEMAS:
# 1. Server action [CREATE] =  '{ "action":"create", "room_name":"some name chosen by admin", "room_welcome_message":"some message set by admin", "room_id":"NSFW", "room_owner":"admin username", "room_password":"MyDirtyRoom123"}'
# 2. Server action [DELETE] =  TODO()
# 3. Server action [JOIN] =  REQUEST: {"action":"join", "user_id":user_id, "username":username}, RESPONSE: {"code": 200, "message":"join success", "room_welcome_message":"welcome, {username}!"}
# 4. Server action [LIST] =  REQUEST: { "action":"list"}, RESPONSE: { "code": 200, "message":"list rooms success", "data":[{"room_name":"Farid's room", "room_id":"room's id", "room_owner":"farid_admin0"}, {}, {}]}

# ROOM SCHEMAS:
# 1. Room action [SEND_MESSAGE] = REQUEST: {"action":"send_message", "user_id":user_id, "message": "hi guys!"}


# GLOBAL VARIABLES
client_socket: socket
sys_input = CustomInput()
user_id = str(uuid.uuid4())
user_mode: str
admin_username: str = None
current_user: str = None


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
        host = "192.168.2.6"#input("Enter server IP: ")  # Server's IP
    port = server_port  # Server's port
    client_socket.connect((host, port))
    return client_socket


# SERVER ACTIONS
def list_rooms():
    # SEND A LIST ACTION REQUEST: {"action":"list_rooms"}
    os.system('cls')
    body = {"action": "list_rooms"}
    client_socket.sendall(json.dumps(body).encode('utf-8'))
    # GET AN ACTION RESPONSE: { "code": 200, "message":"list rooms success", "data":[{"room_name":"Farid's room", "id":"room's id", "owner":"farid_admin0"}, {}, {}]}
    response = json.loads(client_socket.recv(1024).decode('utf-8'))
    # Handle error case here
    if response["code"] != 200: return print(response["message"])
    # Handle success case here
    rooms = response['data']
    print(f"\nAvailable rooms:\n")
    for room in rooms:
        print(f"Room: {room['room_name']}")
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
    # GET AN ACTION RESPONSE: { "code": 200,  "message":"list users success", "data":[{"username":"natig" #(lowercased), "password":"1234"}, {}, {}]}
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
        send_message(message)


def launch_admin_mode(rooms):
    global admin_username
    if not admin_username:
        admin_username = current_user

    choice = input("Please, pick an action [create/delete/join]:\n")

    if choice == "create":
        # { "action":"create", "room_name":"some name chosen by admin", "room_welcome_message":"some message set by admin", "room_id":"NSFW", "room_owner":"admin username", "room_password":"MyDirtyRoom123"}
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
    room_id = input("Please enter a room id from the list above to join: ")
    for room in rooms:
        if room["room_id"] == room_id:
            join_room(room)
            return
    print("No such room exists")


def get_hash(string):
    byte_string = string.encode('utf-8')
    hash_object = hashlib.sha256(byte_string)
    # Get the hexadecimal representation of the hash
    hash_hex = hash_object.hexdigest()

    return hash_hex


def launch_lobby(is_first_time):
    global client_socket
    global user_mode
    global current_user
    if is_first_time:
        print("Welcome to NFV Messenger!")
    else:
        client_socket.close()

    # Connect to the server lobby (static port: 3169)
    client_socket = create_client_socket(3169)
    if is_first_time:
        while True:
            print("To be able to continue you need an account.")
            choice = input("Do you have an account: login (1) or register (2): ")
            if choice == "1":
                client_login()
                break
            elif choice == "2":
                client_register()
                break
            else:
                print("Invalid input!")

    while True:
        choice = input("\nDo you want to send a direct message (1) or to join a room (2): ")
        if choice == "1":
            users = get_users()
            print("NFV Messenger users:\n")
            for user in users:
                print(f"User: {user['username']}")
                print("---------------------------------------------------------")
            while True:
                receiver = input("Enter user you want to send message('exit' to navigate back): ")
                if receiver == "exit":
                    launch_lobby(False)
                    return
                elif receiver not in [user['username'] for user in users]:
                    print("User not found!\n")
                else:
                    break
            type_print("\nWaiting the receiver to come online...")
            type_print("But you can still type your message, receiver will see it whenever they connects.")
            # TODO -> sender server kimi olacaq, receiver birbasa bunun portuna qosulsun

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


def client_login():
    global current_user
    users = get_users()
    while True:
        username = input("Enter your username: ").lower()
        password = sys_input.input("Enter your password: ", mask='*')
        password = get_hash(password)
        user = next((user for user in users if user['username'] == username and user['password'] == password), None)
        if user:
            current_user = username
            launch_lobby(False)
            break
        else:
            print("Wrong username or password!\n")


def client_register():
    global current_user
    users = get_users()
    while True:
        username = input("Enter a username: ").lower()
        if username in [user['username'] for user in users]:
            print("Username already taken! Please choose another one.\n")
        else:
            break
    password = input("Enter a password: ")
    user_data = {
        "username": username,
        "password": get_hash(password),
        "date_joined": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    data = {"action": "add_user", username: user_data}
    client_socket.sendall(json.dumps(data).encode('utf-8'))
    current_user = username
    launch_lobby(False)

if __name__ == "__main__":
    try:
        launch_lobby(True)
    except KeyboardInterrupt:
        print("\nBye!")
        client_socket.close()
    except Exception as e:
        print(f"Something went very wrong! {e} Shutting down...")
    # signal.signal(signal.SIGINT, sigint_handler)