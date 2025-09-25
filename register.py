# register_user.py
import json, socket, getpass, os, hashlib
from dr_common import *
from base64 import b64encode

HOST="127.0.0.1"
PORT=5000
USER_FILE="users.json"

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt, dk

def register_user():
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ").strip()

    # Generate keys
    sk, pk = gen_x25519_keypair()

    # Save private key locally
    with open(f"{username}_sk.bin","wb") as f:
        f.write(sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save credentials locally (hashed)
    if os.path.exists(USER_FILE):
        with open(USER_FILE,"r") as f:
            users = json.load(f)
    else:
        users = {}

    if username in users:
        print("Username already exists!")
        return

    salt, dk = hash_password(password)
    users[username] = {"salt":b64(salt),"hash":b64(dk)}

    with open(USER_FILE,"w") as f:
        json.dump(users,f)

    # Register public key on server
    s = socket.socket()
    s.connect((HOST, PORT))
    msg = {"cmd":"register","user_id":username,"pubkey":b64(pk_bytes(pk))}
    s.send(json.dumps(msg).encode())
    resp = json.loads(s.recv(65536).decode())
    print(f"Registered {username}: {resp}")
    s.close()

if __name__=="__main__":
    register_user()
