# server.py - Server for Double Ratchet Chat
import socket, threading, json
from base64 import b64encode, b64decode
import time

HOST = "127.0.0.1"
PORT = 5000

# Store messages for Alice and Bob
messages = {"Alice": [], "Bob": []}
# Store all messages for Malory to intercept
all_messages = []
# Store public keys for key exchange
public_keys = {}

lock = threading.Lock()

def handle_client(conn, addr):
    print(f"🔗 Client connected: {addr}")
    try:
        while True:
            data = conn.recv(65536)
            if not data: 
                break
                
            msg = json.loads(data.decode())
            cmd = msg.get("cmd")
            
            if cmd == "register_public_key":
                user = msg["user"]
                public_key = msg["public_key"]
                
                with lock:
                    public_keys[user] = public_key
                    
                print(f"🔑 Registered public key for {user}")
                conn.send(json.dumps({"status": "ok"}).encode())
                
            elif cmd == "get_public_key":
                user = msg["user"]
                
                with lock:
                    if user in public_keys:
                        response = {
                            "status": "ok",
                            "public_key": public_keys[user]
                        }
                    else:
                        response = {
                            "status": "error",
                            "error": f"Public key for {user} not found"
                        }
                        
                conn.send(json.dumps(response).encode())
                
            elif cmd == "send_message":
                sender = msg["from"]
                recipient = msg["to"]
                header = msg["header"]
                ciphertext = msg["ciphertext"]
                mac = msg["mac"]
                ad = msg["ad"]
                
                with lock:
                    # Store message for recipient
                    message_data = {
                        "from": sender,
                        "to": recipient,
                        "header": header,
                        "ciphertext": ciphertext,
                        "mac": mac,
                        "ad": ad,
                        "timestamp": time.time()
                    }
                    
                    # Add to recipient's inbox
                    if recipient in messages:
                        messages[recipient].append(message_data)
                    else:
                        messages[recipient] = [message_data]
                    
                    # Store for Malory to intercept (all messages)
                    all_messages.append(message_data.copy())
                    
                    print(f"📨 Double Ratchet message from {sender} to {recipient}")
                
                conn.send(json.dumps({"status": "delivered"}).encode())
                
            elif cmd == "fetch_messages":
                user = msg["user"]
                
                with lock:
                    user_messages = messages.get(user, [])
                    messages[user] = []  # Clear messages after fetching
                
                response = {
                    "status": "ok",
                    "messages": user_messages
                }
                conn.send(json.dumps(response).encode())
                
            elif cmd == "spy_messages":
                # Special command for Malory to intercept all messages
                with lock:
                    response = {
                        "status": "ok",
                        "all_messages": all_messages.copy()
                    }
                conn.send(json.dumps(response).encode())
                print("🕵️ Malory intercepted all Double Ratchet messages!")
                
            else:
                conn.send(json.dumps({"status": "error", "error": "unknown command"}).encode())
                
    except Exception as e:
        print(f"❌ Client error: {e}")
    finally:
        conn.close()
        print(f"🔌 Client disconnected: {addr}")

def serve():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"🚀 Double Ratchet Server listening on {HOST}:{PORT}")
    print("� Ready to relay encrypted Double Ratchet messages")
    print("🔑 Handling public key exchange for DH ratcheting")
    print("🕵️ Malory can intercept all ciphertext...")
    print("-" * 60)
    
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    serve()
