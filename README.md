# NFV Messenger
Disclaimer! This project contains functional, secure rooms.\
Users with different modes can create or join rooms, send messages, and execute special action commands in the system designed for privacy and scalability.


## Control types of users
The server runs continuously, handling multiple clients through threaded connections, differentiating users by their role (admin or standard user).\
Admins can create and delete rooms, while standard users have only access to join available rooms.\
Admin can create rooms and customize almost everything in the room, such as room_id, room_name, room_port, room_timeout, room_type (private or public), room_password. 

## Timeout for rooms
Users can see list of rooms and see even users username's in the room. If a user disconnects, the server removes them from the room. If the last user leaves the room, it checks whether the room should close based on its timeout settings. 

## Room types and Listing
After deciding control type, users see available rooms as a list with active users for each.\
There are two types of rooms - public and private rooms in NFV Messenger. The first is open rooms, anyone can join and chat there. There is no passcode required. Private rooms have predefined passwords, so only eligible users can join these rooms.

## Chat history and Logging
In order to keep track of messages during room sessions (storing previous messages) server collects encrypted data. The main logic is same as the discord chat history logic. For direct messages, the chat history is not stored.\
The almost every operation is reported as logs and collected in server.log file. The logs for actions are detailed, and private data like room messages are logged in an encrypted way.

## User database and credentials
We have a json datalist to store info of users. The passwords are stored as hash values (using sha-256 algorithm) for better integrity and security.\
Apart, users can login to the system, register for a new account, or change their credentials.
Plus, every credential that seems on the terminal is replaced by a mask.

## Encryption in rooms
The chatroom encryption has a bit different logic from E2E. Simply, the newly-joined users exhange digital certificates with the server, and every step of communication between parties.\
Clients create a symmetric key, encrypt it with the server's public key, and sends it to the server, which decrypts it with its private key to establish a secure session for communication.\

## End-to-End encryption
The project has a simple, secure direct messaging part that uses end-to-end encryption to ensure privacy of messages exchanged between parties.\
Parties exchange their public RSA keys using asymmetric key exchange method, so encrypted messages are protected from interception. You can test it using wireshark (we have left basic form of communication without encryption in the comments).\
And we used threading for handling messages simultaneously.\


# Contributors - NFV
Natig Mammadov\
Farid Guliyev\
Vusat (Kematian) Orujov
