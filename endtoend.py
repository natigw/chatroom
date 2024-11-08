import socket
import sys
import threading
import time
import rsa



def type_print(message, typing_speed=0.05):
    for char in message:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(typing_speed)
    print()  # For new line after the message

public_key, private_key = rsa.newkeys(1024)

choice = input("Do you want to Host(1) or to Connect(2): ")

if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('192.168.179.150', 9999))
    server.listen(1)
    type_print("\nServer has run successfully!\n", 0.02)
    client, _ = server.accept()

    client.send(public_key.save_pkcs1("PEM"))
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))

elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('192.168.179.150', 9999))
    type_print("\nConnection established with Partner!\n", 0.02)
    type_print("   *** End-to-End Encryption ***   \n")

    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(public_key.save_pkcs1("PEM"))

else:
    print("Wrong choice!")
    exit()


def send_message(c):
    while True:
        message = input(">> ")
        c.send(message.encode())
        #c.send(rsa.encrypt(message.encode(), public_partner))

def receive_message(c):
    while True:
        message = c.recv(1024).decode()
        #message = rsa.decrypt(c.recv(1024), private_key).decode()
        print(message)

threading.Thread(target=send_message, args=(client,)).start()
threading.Thread(target=receive_message, args=(client,)).start()
