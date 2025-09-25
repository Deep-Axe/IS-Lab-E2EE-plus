# server.py
import socket, threading, json
from base64 import b64encode, b64decode

HOST = "127.0.0.1"
PORT = 5000

# User registry: {user_id: public_key_b64}
users = {}
# Undelivered messages: {user_id: [message_dicts]}
undelivered = {}

lock = threading.Lock()

def handle_client(conn, addr):
    print("Connected", addr)
    try:
        while True:
            data = conn.recv(65536)
            if not data: break
            msg = json.loads(data.decode())
            cmd = msg.get("cmd")
            if cmd == "register":
                user_id = msg["user_id"]
                pubkey = msg["pubkey"]
                with lock:
                    users[user_id] = pubkey
                    undelivered[user_id] = []
                conn.send(json.dumps({"status":"ok"}).encode())
            elif cmd == "list_users":
                with lock:
                    # send mapping user_id -> pubkey
                    conn.send(json.dumps({"users":users}).encode())
            elif cmd == "send_message":
                recipient = msg["to"]
                with lock:
                    if recipient in undelivered:
                        undelivered[recipient].append(msg)
                        conn.send(json.dumps({"status":"sent"}).encode())
                    else:
                        conn.send(json.dumps({"status":"error","error":"recipient not found"}).encode())
            elif cmd == "fetch_messages":
                user_id = msg["user_id"]
                with lock:
                    msgs = undelivered.get(user_id, [])
                    undelivered[user_id] = []
                conn.send(json.dumps({"messages":msgs}).encode())
    except Exception as e:
        print("Client error:", e)
    finally:
        conn.close()

def serve():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print("Server listening", HOST, PORT)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__=="__main__":
    serve()
