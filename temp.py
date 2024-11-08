import json
import time

try:
    with open("users.json", "r") as file:
        _users = json.load(file)  # Initialize _users by loading from the file if it exists
except (FileNotFoundError, json.JSONDecodeError):
    _users = {}                   # Initialize as empty if file is missing or invalid


#add a new user, if exists update it
def add_user(user_data):
    #user_data = {"natig": {"username": "natig", "password": "123", "date_joined": time.strftime('%Y-%m-%d %H:%M:%S')}}
    global _users
    _users.update(user_data)
    with open("users.json", "w") as file:
        json.dump(_users, file, indent=4)
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {user_data} added.")


def get_users():
    return [
        {
            "username": data["username"],
            "password": data["password"],
            "date_joined": data["date_joined"]
        }
        for data in _users.values()
    ]


if __name__ == '__main__':
    add_user({
        "natig": {
            "username": "natig",
            "password": "123",
            "date_joined": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    })
    add_user({
        "vusat": {
            "username": "vusat",
            "password": "salam",
            "date_joined": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    })
