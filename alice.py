# alice.py - Alice with Double Ratchet Implementation
import socket
import json
import os
from base64 import b64encode, b64decode
from double_ratchet import *
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"
PORT = 5000

class Alice:
    def __init__(self):
        self.name = "Alice"
        self.ratchet_state = None
        self.initialized = False
        
    def initialize_session_with_bob(self, bob_public_key_b64):
        """Initialize Double Ratchet session with Bob"""
        try:
            # Shared secret (in real implementation, this would come from X3DH)
            shared_secret = b"alice_bob_shared_secret_demo_key_32bytes!"[:32]
            
            # Deserialize Bob's public key
            bob_public_key_bytes = b64decode(bob_public_key_b64.encode())
            bob_public_key = x25519.X25519PublicKey.from_public_bytes(bob_public_key_bytes)
            
            # Initialize as sender (Alice sends first)
            self.ratchet_state = RatchetInitSender(shared_secret, bob_public_key)
            self.initialized = True
            
            print(f"✅ Double Ratchet session initialized with Bob")
            return True
            
        except Exception as e:
            print(f"❌ Failed to initialize session: {e}")
            return False
    
    def get_bob_public_key(self):
        """Get Bob's public key from server"""
        try:
            s = socket.socket()
            s.connect((HOST, PORT))
            
            msg_data = {
                "cmd": "get_public_key",
                "user": "Bob"
            }
            
            s.send(json.dumps(msg_data).encode())
            response = json.loads(s.recv(4096).decode())
            s.close()
            
            if response["status"] == "ok":
                return response["public_key"]
            else:
                print(f"❌ Error getting Bob's public key: {response.get('error', 'Unknown error')}")
                return None
                
        except Exception as e:
            print(f"❌ Error getting Bob's public key: {e}")
            return None
    
    def ensure_session_initialized(self):
        """Ensure Double Ratchet session is initialized"""
        if not self.initialized:
            bob_public_key = self.get_bob_public_key()
            if bob_public_key:
                return self.initialize_session_with_bob(bob_public_key)
            return False
        return True
    
    def send_message(self, message):
        """Send encrypted message using Double Ratchet"""
        if not self.ensure_session_initialized():
            print("❌ Cannot send message - session not initialized")
            return
            
        try:
            # Encrypt using Double Ratchet
            AD = b"alice_to_bob"  # Associated data
            header, ciphertext = RatchetEncrypt(self.ratchet_state, message.encode(), AD)
            
            # Prepare message for server
            msg_data = {
                "cmd": "send_message",
                "from": self.name,
                "to": "Bob", 
                "header": header.serialize(),
                "ciphertext": serialize(ciphertext[0]),
                "mac": serialize(ciphertext[1]),
                "ad": serialize(AD)
            }
            
            # Send to server
            s = socket.socket()
            s.connect((HOST, PORT))
            s.send(json.dumps(msg_data).encode())
            response = json.loads(s.recv(1024).decode())
            s.close()
            
            if self.ratchet_state is not None:
                print(f"✅ Double Ratchet message sent! (Ns: {self.ratchet_state['Ns']-1})")
            else:
                print("❌ Error: Ratchet state is None after sending")
            
        except Exception as e:
            print(f"❌ Error sending message: {e}")
    
    def fetch_messages(self):
        """Fetch and decrypt messages using Double Ratchet"""
        try:
            s = socket.socket()
            s.connect((HOST, PORT))
            
            msg_data = {
                "cmd": "fetch_messages",
                "user": self.name
            }
            
            s.send(json.dumps(msg_data).encode())
            response = json.loads(s.recv(8192).decode())
            s.close()
            
            if response["status"] == "ok":
                messages = response["messages"]
                if not messages:
                    print("📪 No new messages from Bob")
                else:
                    print(f"📬 Received {len(messages)} message(s):")
                    for msg in messages:
                        try:
                            # Deserialize message components
                            header = Header.deserialize(msg["header"])
                            ciphertext = (deserialize(msg["ciphertext"]), deserialize(msg["mac"]))
                            AD = deserialize(msg["ad"])
                            
                            # Decrypt using Double Ratchet
                            if not self.initialized:
                                # If not initialized, initialize as receiver
                                shared_secret = b"alice_bob_shared_secret_demo_key_32bytes!"[:32]
                                bob_dh_key = x25519.X25519PublicKey.from_public_bytes(header.dh)
                                self.ratchet_state = RatchetInitReceiver(shared_secret, bob_dh_key)
                                self.initialized = True
                            
                            plaintext = RatchetDecrypt(self.ratchet_state, header, ciphertext, AD)
                            print(f"  💬 Bob: {plaintext.decode()}")
                            
                        except Exception as e:
                            print(f"  ❌ Failed to decrypt message from Bob: {e}")
            else:
                print(f"❌ Error fetching messages: {response.get('error', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ Error fetching messages: {e}")
    
    def register_public_key(self):
        """Register our DH public key with server"""
        if not self.initialized:
            if not self.ensure_session_initialized():
                return
                
        try:
            # Get our current DH public key
            if self.ratchet_state is None:
                print("❌ Error: Ratchet state is None")
                return
                
            public_key = self.ratchet_state["DHs"].public_key()
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            s = socket.socket()
            s.connect((HOST, PORT))
            
            msg_data = {
                "cmd": "register_public_key",
                "user": self.name,
                "public_key": b64encode(public_key_bytes).decode()
            }
            
            s.send(json.dumps(msg_data).encode())
            response = json.loads(s.recv(1024).decode())
            s.close()
            
            if response["status"] == "ok":
                print("✅ Public key registered with server")
            else:
                print(f"❌ Failed to register public key: {response.get('error', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ Error registering public key: {e}")
    
    def show_ratchet_state(self):
        """Show current Double Ratchet state for debugging"""
        if not self.initialized:
            print("❌ Double Ratchet not initialized")
            return
            
        state = self.ratchet_state
        if state is None:
            print("❌ Double Ratchet not initialized")
            return
            
        print(f"🔧 Double Ratchet State:")
        print(f"   Send Counter (Ns): {state['Ns']}")
        print(f"   Receive Counter (Nr): {state['Nr']}")
        print(f"   Previous Chain Length (PN): {state['PN']}")
        print(f"   Skipped Messages: {len(state['MKSKIPPED'])}")
        print(f"   Send Chain Key: {'Present' if state['CKs'] else 'None'}")
        print(f"   Receive Chain Key: {'Present' if state['CKr'] else 'None'}")
    
    def interactive_mode(self):
        """Interactive chat mode for Alice with Double Ratchet"""
        print(f"🔐 {self.name} - Double Ratchet Secure Chat")
        print("Commands: send <message>, fetch, register, state, quit")
        print("=" * 50)
        
        # Register public key on startup
        self.register_public_key()
        
        while True:
            try:
                cmd = input(f"{self.name}> ").strip()
                
                if cmd.lower() == "quit":
                    break
                elif cmd.startswith("send "):
                    message = cmd[5:]  # Remove "send "
                    self.send_message(message)
                elif cmd.lower() == "fetch":
                    self.fetch_messages()
                elif cmd.lower() == "register":
                    self.register_public_key()
                elif cmd.lower() == "state":
                    self.show_ratchet_state()
                else:
                    print("Commands: send <message>, fetch, register, state, quit")
                    
            except KeyboardInterrupt:
                break
        
        print(f"👋 {self.name} disconnected")

if __name__ == "__main__":
    alice = Alice()
    alice.interactive_mode()