# enhanced_alice.py (Modified for Demonstration)

import socket
import json
import time
from base64 import b64encode, b64decode
from typing import Optional
from cryptography.hazmat.primitives import serialization

try:
    from core.double_ratchet import DoubleRatchetSession
    from utils.state_manager import StateManager
    from utils.message_handler import MessageHandler
    from utils.error_handler import ErrorHandler, ErrorCode, create_crypto_error, create_network_error
    from security.x3dh_integration import X3DHSession
except ImportError:
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from core.double_ratchet import DoubleRatchetSession
    from utils.state_manager import StateManager
    from utils.message_handler import MessageHandler
    from utils.error_handler import ErrorHandler, ErrorCode, create_crypto_error, create_network_error
    from security.x3dh_integration import X3DHSession, PreKeyServer

from cryptography.hazmat.primitives.asymmetric import x25519

class EnhancedAliceClient:
    def __init__(self):
        self.error_handler = ErrorHandler()
        self.state_manager = StateManager(self.error_handler)
        self.message_handler = MessageHandler()
        self.x3dh_session = X3DHSession(self.error_handler)
        
        self.client_socket: Optional[socket.socket] = None
        self.alice_session: Optional[DoubleRatchetSession] = None
        self.session_initialized = False
        self.identity_key: Optional[x25519.X25519PrivateKey] = None
        self.recipient_identity_key: Optional[x25519.X25519PublicKey] = None
        
        self.client_id = "Alice"
        self.server_host = 'localhost'
        self.server_port = 9999
        self.state_password = "alice_secure_password_123"
    
    def connect_to_server(self):
        def _connect():
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)
            self.client_socket.connect((self.server_host, self.server_port))
            return True
        
        success, _, error_info = self.error_handler.retry_operation(_connect, max_retries=3)
        
        if success:
            print("Alice connected to server")
            return True
        else:
            print(f"Alice failed to connect: {error_info}")
            return False
    
    def load_or_create_session(self):
        try:
            if self.state_manager.state_exists(self.client_id):
                print("Alice: Loading existing session state...")
                state_data = self.state_manager.load_state(self.client_id, self.state_password)
                self.alice_session = DoubleRatchetSession()
                self.alice_session.restore_state(state_data['ratchet_state'])
                self.session_initialized = True

                sealed_state = state_data.get('sealed_sender', {})
                identity_b64 = sealed_state.get('identity_private')
                if identity_b64:
                    try:
                        identity_bytes = b64decode(identity_b64)
                        self.identity_key = x25519.X25519PrivateKey.from_private_bytes(identity_bytes)
                    except Exception:
                        self.identity_key = None
                peer_b64 = sealed_state.get('peer_identity_public')
                if peer_b64:
                    try:
                        peer_bytes = b64decode(peer_b64)
                        self.recipient_identity_key = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
                    except Exception:
                        self.recipient_identity_key = None
                print("Alice: Session state restored successfully")
                return True
            else:
                print("Alice: No existing session found, will create new one")
                return False
        except Exception as e:
            self.error_handler.handle_error(e, "load_or_create_session")
            print("Alice: Failed to load existing session, will create new one")
            return False
    
    def perform_x3dh_key_exchange(self):
        try:
            if not self.client_socket: return False
            if not self.identity_key:
                self.identity_key = self.x3dh_session.generate_identity_key()
            alice_identity_key = self.identity_key
            alice_ephemeral_key = x25519.X25519PrivateKey.generate()
            
            alice_bundle = {
                'identity_key': b64encode(alice_identity_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)).decode(),
                'ephemeral_key': b64encode(alice_ephemeral_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)).decode()
            }
            key_message = {'type': 'x3dh_key_exchange', 'from': self.client_id, 'bundle': alice_bundle}
            self.client_socket.send(json.dumps(key_message).encode())
            print("Alice sent X3DH key bundle")
            
            response = self.client_socket.recv(8192).decode()
            bob_response = json.loads(response)
            
            if bob_response.get('type') == 'x3dh_key_exchange' and bob_response.get('from') == 'Bob':
                bob_bundle = bob_response['bundle']
                print("Alice received Bob's X3DH bundle")
                shared_key, _, _ = self.x3dh_session.perform_x3dh_sender(alice_identity_key, bob_bundle, alice_ephemeral_key)
                try:
                    bob_identity_bytes = b64decode(bob_bundle['identity_key'])
                    self.recipient_identity_key = x25519.X25519PublicKey.from_public_bytes(bob_identity_bytes)
                except Exception:
                    self.recipient_identity_key = None
                
                self.alice_session = DoubleRatchetSession()
                dh_response = self.client_socket.recv(4096).decode()
                dh_message = json.loads(dh_response)
                
                if dh_message.get('type') == 'dh_public_key' and dh_message.get('from') == 'Bob':
                    bob_dh_public_bytes = b64decode(dh_message['dh_public_key'])
                    bob_dh_public_key = x25519.X25519PublicKey.from_public_bytes(bob_dh_public_bytes)
                    self.alice_session.init_alice_with_shared_key(shared_key, bob_dh_public_key)
                    print("Alice received Bob's DH public key and completed initialization")
                else:
                    return False

                self.session_initialized = True
                print("Alice: Double Ratchet session initialized with X3DH")
                self.save_session_state()
                return True
            else:
                return False
        except Exception as e:
            self.error_handler.handle_error(e, "perform_x3dh_key_exchange")
            return False
                
    def fallback_key_exchange(self):
        try:
            if not self.client_socket: return False
            alice_private_key = x25519.X25519PrivateKey.generate()
            alice_public_key = alice_private_key.public_key()
            
            alice_public_bytes = alice_public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            key_message = {'type': 'simple_key_exchange', 'from': self.client_id, 'public_key': b64encode(alice_public_bytes).decode()}
            self.client_socket.send(json.dumps(key_message).encode())
            print("Alice sent public key (fallback mode)")
            
            response = self.client_socket.recv(4096).decode()
            bob_key_data = json.loads(response)
            
            if bob_key_data.get('type') == 'simple_key_exchange' and bob_key_data.get('from') == 'Bob':
                bob_public_bytes = b64decode(bob_key_data['public_key'])
                bob_public_key = x25519.X25519PublicKey.from_public_bytes(bob_public_bytes)
                print("Alice received Bob's public key (fallback mode)")
                
                self.alice_session = DoubleRatchetSession()
                self.alice_session.init_alice(alice_private_key, bob_public_key)
                self.session_initialized = True
                print("Alice: Double Ratchet session initialized (fallback mode)")
                self.save_session_state()
                return True
            else:
                return False
        except Exception as e:
            self.error_handler.handle_error(e, "fallback_key_exchange")
            return False
    
    def save_session_state(self):
        try:
            if self.alice_session and self.session_initialized:
                state_data = {
                    'client_id': self.client_id,
                    'ratchet_state': self.alice_session.get_state(),
                    'last_updated': int(time.time())
                }
                sealed_state = {}
                if self.identity_key:
                    sealed_state['identity_private'] = b64encode(self.identity_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )).decode()
                if self.recipient_identity_key:
                    sealed_state['peer_identity_public'] = b64encode(self.recipient_identity_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )).decode()
                if sealed_state:
                    state_data['sealed_sender'] = sealed_state
                self.state_manager.save_state(self.client_id, state_data, self.state_password)
        except Exception as e:
            self.error_handler.handle_error(e, "save_session_state")
                
    def send_enhanced_message(self, plaintext_message):
        try:
            if not self.session_initialized or not self.alice_session or not self.client_socket:
                print("Alice: Session not ready, cannot send message")
                return False
            
            header, ciphertext, mac, ad, message_key = self.alice_session.ratchet_encrypt(plaintext_message)
            
            print(f"  DEMO KEY: {message_key.hex()}")

            sealed_sender = None
            if self.identity_key and self.recipient_identity_key:
                try:
                    sealed_sender = self.message_handler.create_sealed_sender_envelope(
                        sender_id=self.client_id,
                        sender_identity_key=self.identity_key,
                        recipient_identity_key=self.recipient_identity_key
                    )
                except Exception as envelope_error:
                    print(f"   Sealed sender unavailable: {envelope_error}")
            
            enhanced_message = self.message_handler.create_message(
                from_user=self.client_id, to_user="Bob",
                message_type=self.message_handler.MESSAGE_TYPES['TEXT'],
                header=header, ciphertext=ciphertext, mac=mac, ad=ad,
                plaintext_content=plaintext_message,
                sealed_sender=sealed_sender
            )
            
            message_json = self.message_handler.serialize_message(enhanced_message)
            self.client_socket.send(message_json.encode())
            
            print(f"    Encrypted and sent: '{plaintext_message}'")
            print(f"     Message ID: {enhanced_message['message_id']}")
            print(f"     Sequence: {enhanced_message['sequence_number']}")
            
            self.save_session_state()
            return True
            
        except Exception as e:
            self.error_handler.handle_error(e, "send_enhanced_message")
            return False
    
    def run_session(self):
        try:
            if not self.connect_to_server(): return False
            
            if not self.load_or_create_session():
                print("Alice: Attempting X3DH key exchange...")
                if not self.perform_x3dh_key_exchange():
                    print("Alice: X3DH failed, falling back to simple key exchange...")
                    if not self.fallback_key_exchange():
                        print("Alice: All key exchange methods failed")
                        return False
            
            print("\n" + "="*60)
            print("    ALICE - Interactive Message Sender")
            print("    Type messages to send to Bob (or 'quit' to exit)")
            print("="*60)
            
            message_count = 0
            while True:
                try:
                    user_input = input(f"\nAlice (msg #{message_count + 1}): ").strip()
                    if user_input.lower() in ['quit', 'exit', 'q']: break
                    if not user_input: continue
                    
                    if self.send_enhanced_message(user_input):
                        message_count += 1
                    else:
                        print(f"  ❌ Failed to send message")
                        
                except KeyboardInterrupt:
                    break
            
            print(f"\nAlice: Session ended. {message_count} messages sent.")
            return True
            
        except Exception as e:
            self.error_handler.handle_error(e, "run_session")
            return False
        
        finally:
            if self.client_socket:
                self.client_socket.close()
                print("Alice disconnected from server")

def main():
    alice_client = EnhancedAliceClient()
    try:
        alice_client.run_session()
    except KeyboardInterrupt:
        print("\nAlice session interrupted by user")

if __name__ == "__main__":
    main()