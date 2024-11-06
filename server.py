import json
import socket
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load private key
with open("private_key.pem", "rb") as private_key_file:
    private_key = serialization.load_pem_private_key(
        private_key_file.read(),
        password=None,
    )

# Load public key
with open("public_key.pem", "rb") as public_key_file:
    public_key_pem = public_key_file.read()


def create_socket(port):
    """create a tcp server socket"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    host = socket.gethostbyname(socket.gethostname())
    # log(type(port))
    # log(port == 0)
    s.bind((host, port))  # tell OS to forward these packets to our socket
    s.listen(5)  # backlog of 5 connections, after 5 are in queue, the rest will be refused
    log(f"Started listening on {host}:{s.getsockname()[1]}")
    return s

def log(message):
    open(file="server.log", mode="a").write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}")


# GLOBAL VARIABLES
clients = []
_rooms = {
    "TEST1": {
        "room_name": "some name chosen by admin",
        "room_welcome_message": "WELCOME TO MY VERY FIRST ROOM, ENJOY, NO RULES :D",
        "room_id": "TEST1",
        "room_owner": "admin username",
        "room_password": "123",
        "room_type": "private",
        "room_port": 3170,
        "room_timeout": 20,
        "users": {},  # "4124" : {"user_id": "4124", "username": "farid123", "socket":socket}
        "messages": []
    },
    "general": {
        "room_name": "some name chosen by admin",
        "room_welcome_message": "WELCOME TO MY VERY FIRST ROOM, ENJOY, NO RULES :D",
        "room_id": "general",
        "room_owner": "admin username",
        "room_password": "",
        "room_type": "public",
        "room_port": 3171,
        "room_timeout": 0,
        "users": {},  # "4124" : {"user_id": "4124", "username": "farid123", "socket": socket}
        "messages": []
    }
}

available_commands = ["help - Show all commands | username - Change your username"]


def get_rooms():
    mapped_list = []
    for room_id, room_data in _rooms.items():
        room_name = room_data.get("room_name")
        room_owner = room_data.get("room_owner")
        room_port = room_data.get("room_port")
        room_type = room_data.get("room_type")
        user_count = len(room_data.get("users", {}))  # Count of users
        mapped_list.append({
            "room_name": room_name,
            "room_id": room_id,
            "room_port": room_port,
            "room_owner": room_owner,
            "user_count": user_count,
            "room_type": room_type
        })
    return mapped_list


# rooms = [{"room_name":"Farid's room 1", "room_id":"TEST1", "room_owner":"faridg", "is_private": False, "room_port": 3170}, {"room_name":"Farid's room special", "room_id":"FARIDG", "room_owner":"faridg", "is_private": False, "room_port": 3171}]
server_lobby_socket = create_socket(3169)


def list_rooms(client_socket):
    # { "code": 200,  "message":"list success", "data":[{"room_name":"Farid's room", "id":"room's id", "owner":"farid_admin0"}, {}, {}]}
    response = {"code": 200, "message": "list success", "data": get_rooms()}
    client_socket.sendall(json.dumps(response).encode('utf-8'))


def lobby_client_handler(client_socket):
    while True:
        # receive request
        data = client_socket.recv(1024)
        if not data:
            break
        request = json.loads(data.decode('utf-8'))
        log(f"Lobby received: {request}")
        # identify request type
        if request["action"] == "list":
            list_rooms(client_socket)
        elif request["action"] == "create":
            admin_create_room(request)
        elif request["action"] == "delete":
            admin_delete_room(request)


def admin_create_room(request):
    room_password = request["room_password"]
    if room_password == "":
        room_type = "public"
    else:
        room_type = "private"
    _rooms[request["room_id"]] = {
        "room_name": request["room_name"],
        "room_welcome_message": request["room_welcome_message"],
        "room_id": request["room_id"],
        "room_owner": request["room_owner"],
        "room_password": room_password,
        "room_type": room_type,
        "room_port": request["room_port"],
        "messages": [],
        "room_timeout": request["room_timeout"],
        "users": {}
    }
    start_room(request["room_id"], request["room_port"], request["room_timeout"])


def admin_delete_room(request):
    room_id = request["room_id"]
    room = _rooms[room_id]
    for user_id in list(room["users"].keys())[::]:
        user_socket = room["users"][user_id]["socket"]
        user_socket.close()
        del room["users"][user_id]
    del _rooms[room_id]


def broadcast_message(room, excluded_id, message):
    log(f"Room {room['room_id']} broadcasting message: {message}")
    room["messages"].append(message)
    for user_id in list(room["users"].keys())[::]:
        if user_id != excluded_id:
            log(f"Broadcasting to the user: {user_id}")
            data = {"code": 200, "action": "receive_message", "message": message}
            try:
                user_socket = room["users"][user_id]["socket"]
                fernet = room["users"][user_id]["fernet"]
                send_request_encrypted(json.dumps(data).encode('utf-8'), fernet, user_socket)
                # room["users"][user_id]["socket"].sendall(json.dumps(data).encode('utf-8'))  # Send message
            except:
                username = room["users"][user_id]["username"]
                del room["users"][user_id]
                disconnect_message = f"User {username} disconnected"
                broadcast_message(room, user_id, disconnect_message)


def send_request_encrypted(data, fernet, client_socket):
    encrypted_data = fernet.encrypt(data)
    client_socket.sendall(encrypted_data)


def receive_encrypted_data(data, fernet):
    log(f"Received raw data: {data}")
    decrypted_data = fernet.decrypt(data)
    log(f"Decrypted data: {decrypted_data}")
    return decrypted_data


def room_client_handler(room_id, client_socket, room_socket):
    # Send public key to client once connected!
    client_socket.sendall(public_key_pem)
    log("Public key sent to client.")

    room = _rooms[room_id]
    this_client_id: str
    last_received_raw_data = None
    fernet = None
    while True:
        try:
            # receive request
            try:
                last_received_raw_data = client_socket.recv(4096)
            except ConnectionResetError:
                client_socket.close()
                broadcast_message(room, this_client_id, f"User {room[this_client_id]['username']} left the room!")
                del room["users"][this_client_id]
                room_timeout_handler(room_id, room_socket, room["room_timeout"])
                break

            request = json.loads(receive_encrypted_data(last_received_raw_data, fernet).decode('utf-8'))
            log(f"Room {room_id} received a request: {request}")
            # identify request type
            if request["action"] == "unlock":
                if request["room_password"] == room["room_password"]:
                    body = {"code": 200, "message": "Password is valid"}
                else:
                    body = {"code": 401, "message": "Invalid password!"}
                send_request_encrypted(json.dumps(body).encode('utf-8'), fernet, client_socket)
                # client_socket.sendall(json.dumps(body).encode('utf-8'))
            elif request["action"] == "join":
                username = request["username"]
                username_exists = False
                for user in room["users"].values():
                    if user["username"] == username:
                        body = {"code": 400, "message": "Username already exists!"}
                        log("Username exists!!!")
                        send_request_encrypted(json.dumps(body).encode('utf-8'), fernet, client_socket)
                        username_exists = True
                        break
                if username_exists:
                    continue
                this_client_id = request["user_id"]
                room["users"][request["user_id"]] = {"user_id": this_client_id, "username": request["username"],
                                                     "socket": client_socket, "fernet": fernet}
                body = {"code": 200, "message": "join success", "room_welcome_message": room["room_welcome_message"]}
                send_request_encrypted(json.dumps(body).encode('utf-8'), fernet, client_socket)
                body = {"code": 200, "messages": room["messages"]}
                send_request_encrypted(json.dumps(body).encode('utf-8'), fernet, client_socket)
                # client_socket.sendall(json.dumps(body).encode('utf-8'))
                # Broadcast the message to others about the user's join (client itself excluded)
                broadcast_message(room, this_client_id, f'User {request["username"]} joined the room!')

            elif request["action"] == "send_message":
                # Broadcast the message to others (client itself excluded)
                broadcast_message(room, this_client_id,
                                  f'{room["users"][this_client_id]["username"]}: {request["message"]}')
            elif request["action"] == "command":
                log(f"Command received: {request['action']}")
                # Execute commands
                if request["command"] == "help":
                    body = {"code": 200, "action": "receive_message",
                            "message": f"List of available commands: {available_commands}"}
                    # client_socket.sendall(json.dumps(body).encode('utf-8'))
                    send_request_encrypted(json.dumps(body).encode('utf-8'), fernet, client_socket)
                elif request['command'] == "username":
                    oldUsername = room['users'][this_client_id]['username']
                    newUsername = request['value']
                    room['users'][this_client_id]['username'] = newUsername
                    broadcast_message(room, "", f"{oldUsername} changed their username to {newUsername}")
                elif request['command'] == "quit":
                    body = {"code": 200, "action": "leave_room",
                            "message": "You left the room!"}
                    # client_socket.sendall(json.dumps(body).encode('utf-8'))
                    send_request_encrypted(json.dumps(body).encode('utf-8'), fernet, client_socket)
                    broadcast_message(room, this_client_id,
                                      f"User {room['users'][this_client_id]['username']} left the room!")
                    del room["users"][this_client_id]
                    client_socket.close()
                    room_timeout_handler(room_id, room_socket, room["room_timeout"])
                    return
                else:
                    body = {"code": 400, "action": "receive_message",
                            "message": "Command is not recognized, use /help to get a list of available commands!"}
                    # client_socket.sendall(json.dumps(body).encode('utf-8'))
                    send_request_encrypted(json.dumps(body).encode('utf-8'), fernet, client_socket)

        except Exception:
            # If it is not json, then it is an encryption key
            if not last_received_raw_data:
                pass
            else:
                # Receive encrypted key from client
                encrypted_message = last_received_raw_data
                # Decrypt message with private key
                key = private_key.decrypt(
                    encrypted_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                log(f"Decrypted key: {key}")
                fernet = Fernet(key)
                log(f"Key received: {fernet}")

def room_timeout_handler(room_id, room_socket, timeout):
    log(f"{len(_rooms[room_id]['users'])} users in the room. Timeout: {timeout}, {room_id} room, {room_socket}")
    if timeout == 0:
        return
    if len(_rooms[room_id]["users"]) == 0:
        time.sleep(timeout)
        print(f"{timeout} seconds passed.")
        if len(_rooms[room_id]["users"]) == 0:
            log(f"Room {room_id} is empty, closing it.")
            room_socket.close()
            del _rooms[room_id]

def start_room(room_id, port, timeout):
    # CREATE A NEW ROOM
    room_socket = create_socket(port)
    # ROOM LOGIC
    room_timer = threading.Thread(target=room_timeout_handler, args=(
        room_id, room_socket, timeout))  # Create a new thread to handle the connection (parallelism)
    room_timer.start()
    while True:
        try:
            # wait for the incoming requests (blocking function)
            client_socket, client_address = room_socket.accept()
            log(f"ROOM: Connection established with {client_address}")
            # handle each client request in a separate thread
            room_handler = threading.Thread(target=room_client_handler, args=(
                room_id, client_socket,room_socket))  # Create a new thread to handle the connection (parallelism)
            room_handler.start()
        except Exception as e:
            break

def start_lobby():
    # SERVER LOBBY LOGIC
    while True:
        # wait for the incoming requests (blocking function)
        client_socket, client_address = server_lobby_socket.accept()
        log(f"LOBBY: Connection established with {client_address}")
        # handle each client request in a separate thread
        lobby_handler = threading.Thread(target=lobby_client_handler, args=(
            client_socket,))  # Create a new thread to handle the connection (parallelism)
        lobby_handler.start()


# Launch initial rooms
for room in _rooms.values():
    room_thread = threading.Thread(target=start_room, args=(room['room_id'], room['room_port'], room['room_timeout']))
    room_thread.start()

# Launch the lobby
lobby_thread = threading.Thread(target=start_lobby)
lobby_thread.start()
lobby_thread.join()