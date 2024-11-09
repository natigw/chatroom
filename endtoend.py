import os
import socket
import sys
import threading
import time

import rsa

HOSTNAME = socket.gethostname()
IP_ADDRESS = socket.gethostbyname(HOSTNAME)
PORT = 9999

def type_print(message, typing_speed=0.05):
    for char in message:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(typing_speed)
    print()  #for new line after the message

public_key_endtoend, private_key_endtoend = rsa.newkeys(1024)

choice = input("Do you want to Host(1) or to Connect(2): ")

if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP_ADDRESS, PORT))
    server.listen(1)
    os.system('cls')
    type_print("\nHost server has run successfully!\n", 0.02)
    client, _ = server.accept()

    # Exchange public keys
    client.send(public_key_endtoend.save_pkcs1("PEM"))
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))

elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = input("Enter Sender's IP address: ")
    port = int(input("Enter Sender's Port number: "))
    client.connect((ip, port))
    os.system('cls')
    type_print("\nConnection established with Partner!\n", 0.02)
    type_print("   *** End-to-End Encryption ***   \n")

    # Exchange public keys
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(public_key_endtoend.save_pkcs1("PEM"))

else:
    print("Wrong choice!")
    exit()


def send_message(c):
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
        #c.send(rsa.encrypt(message.encode(), public_partner))

def receive_message(c):
    while True:
        message = c.recv(1024).decode()
        #message = rsa.decrypt(c.recv(1024), private_key).decode()
        if message == "[End of Connection]":
            type_print("\n\n Partner says GoodBye to you! ")
            time.sleep(3)
            os.system('cls')
            type_print("\nConnection has been ended!")
            return
        print(f">> {message}")

threading.Thread(target=send_message, args=(client,)).start()
threading.Thread(target=receive_message, args=(client,)).start()