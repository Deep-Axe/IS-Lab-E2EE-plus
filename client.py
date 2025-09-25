# client.py
import socket, json, time, getpass, os, hashlib
from dr_common import *
from base64 import b64decode, b64encode

HOST="127.0.0.1"
PORT=5000
USER_FILE="users.json"

def verify_password(stored_salt, stored_hash, password):
    salt = ub64(stored_salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return dk == ub64(stored_hash)

class Client:
    def __init__(self, user_id):
        self.user_id = user_id
        # load private key
        with open(f"{user_id}_sk.bin","rb") as f:
            sk_bytes = f.read()
        self.sk = x25519.X25519PrivateKey.from_private_bytes(sk_bytes)
        self.sessions = {}  # per recipient: RK, CKs, CKr, etc.

    def get_users(self):
        s = socket.socket()
        s.connect((HOST, PORT))
        s.send(json.dumps({"cmd":"list_users"}).encode())
        resp = json.loads(s.recv(65536).decode())
        s.close()
        return {uid:pk for uid,pk in resp["users"].items() if uid!=self.user_id}

    def init_session(self, recipient_id, recipient_pub_b64):
        if recipient_id in self.sessions:
            return
        their_pk = pk_from_bytes(b64decode(recipient_pub_b64))
        dh_out = dh(self.sk, their_pk)
        root_key = hkdf(b"", dh_out, b"init", 32)
        CKs = hkdf(root_key, b"CKs", b"CKs", 32)
        CKr = hkdf(root_key, b"CKr", b"CKr", 32)
        self.sessions[recipient_id] = {"RK":root_key,"CKs":CKs,"CKr":CKr,
                                       "Ns":0,"Nr":0,"skipped":{}}

    def send_message(self, recipient_id, plaintext):
        users = self.get_users()
        if recipient_id not in users:
            print("Recipient not found")
            return
        self.init_session(recipient_id, users[recipient_id])
        session = self.sessions[recipient_id]
        next_ck, mk = kdf_chain(session["CKs"])
        session["CKs"] = next_ck
        session["Ns"] +=1
        ct = encrypt_message(mk, plaintext.encode())
        msg = {"cmd":"send_message","from":self.user_id,"to":recipient_id,
               "ct":b64(ct),"n":session["Ns"],"pn":0,"dh":None}
        s = socket.socket()
        s.connect((HOST, PORT))
        s.send(json.dumps(msg).encode())
        resp = json.loads(s.recv(65536).decode())
        print("Send status:", resp)
        s.close()

    def fetch_messages(self):
        s = socket.socket()
        s.connect((HOST, PORT))
        s.send(json.dumps({"cmd":"fetch_messages","user_id":self.user_id}).encode())
        resp = json.loads(s.recv(65536).decode())
        for m in resp["messages"]:
            sender = m["from"]
            if sender not in self.sessions:
                print("Unknown sender, skipping")
                continue
            session = self.sessions[sender]
            next_ck, mk = kdf_chain(session["CKr"])
            session["CKr"] = next_ck
            session["Nr"] +=1
            pt = decrypt_message(mk, b64decode(m["ct"]))
            print(f"📩 Message from {sender}: {pt.decode()}")
        s.close()

def main():
    # Login
    if not os.path.exists(USER_FILE):
        print("No users registered. Run register_user.py first.")
        return
    with open(USER_FILE,"r") as f:
        users = json.load(f)

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ").strip()

    if username not in users or not verify_password(users[username]["salt"], users[username]["hash"], password):
        print("Invalid credentials")
        return

    client = Client(username)
    print(f"✅ Logged in as {username}")

    # Interactive loop
    while True:
        cmd = input(">> ").strip()
        if cmd == "exit":
            break
        elif cmd.startswith("send "):
            try:
                _, recipient, *msg = cmd.split()
                message = " ".join(msg)
                client.send_message(recipient, message)
            except:
                print("Usage: send <recipient> <message>")
        elif cmd == "fetch":
            client.fetch_messages()
        elif cmd == "users":
            print("Users:", client.get_users())
        else:
            print("Commands: send <recipient> <msg>, fetch, users, exit")

if __name__=="__main__":
    main()
