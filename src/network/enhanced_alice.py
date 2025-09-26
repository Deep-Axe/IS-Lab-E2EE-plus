# enhanced_alice.py - Enhanced Alice client with all production-like features
import socket
import json
import time
from base64 import b64encode, b64decode
from typing import Optional
from cryptography.hazmat.primitives import serialization

# Use absolute imports that work both standalone and as package
try:
    from core.double_ratchet import DoubleRatchetSession
    from utils.state_manager import StateManager
    from utils.message_handler import MessageHandler
    from utils.error_handler import ErrorHandler, ErrorCode, create_crypto_error, create_network_error
    from security.x3dh_integration import X3DHSession, PreKeyServer
except ImportError:
    # Fallback for when run as script
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
    """Enhanced Alice client with all production-like features"""
    
    def __init__(self):
        self.error_handler = ErrorHandler()
        self.state_manager = StateManager(self.error_handler)
        self.message_handler = MessageHandler()
        self.x3dh_session = X3DHSession(self.error_handler)
        
        self.client_socket: Optional[socket.socket] = None
        self.alice_session: Optional[DoubleRatchetSession] = None
        self.session_initialized = False
        
        # Client configuration
        self.client_id = "Alice"
        self.server_host = 'localhost'
        self.server_port = 9999
        self.state_password = "alice_secure_password_123"
    
    def connect_to_server(self):
        """Connect to the server with error handling and retry"""
        def _connect():
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)  # 10 second timeout
            self.client_socket.connect((self.server_host, self.server_port))
            return True
        
        success, result, error_info = self.error_handler.retry_operation(_connect, max_retries=3)
        
        if success:
            print("Alice connected to server")
            return True
        else:
            print(f"Alice failed to connect: {error_info}")
            return False
    
    def load_or_create_session(self):
        """Load existing session or create new one"""
        try:
            # Try to load existing state
            if self.state_manager.state_exists(self.client_id):
                print("Alice: Loading existing session state...")
                state_data = self.state_manager.load_state(self.client_id, self.state_password)
                
                # Restore Double Ratchet session
                self.alice_session = DoubleRatchetSession()
                self.alice_session.restore_state(state_data['ratchet_state'])
                self.session_initialized = True
                
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
        """Perform X3DH key exchange for initial session setup"""
        try:
            if not self.client_socket:
                print("Alice: No connection to server")
                return False
                
            # Generate Alice's identity and ephemeral keys
            alice_identity_key = self.x3dh_session.generate_identity_key()
            alice_ephemeral_key = x25519.X25519PrivateKey.generate()
            
            # Send Alice's public keys to server for Bob to fetch
            alice_bundle = {
                'identity_key': b64encode(alice_identity_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )).decode(),
                'ephemeral_key': b64encode(alice_ephemeral_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )).decode()
            }
            
            key_message = {
                'type': 'x3dh_key_exchange',
                'from': self.client_id,
                'bundle': alice_bundle
            }
            
            self.client_socket.send(json.dumps(key_message).encode())
            print("Alice sent X3DH key bundle")
            
            # Receive Bob's bundle
            response = self.client_socket.recv(8192).decode()
            bob_response = json.loads(response)
            
            if bob_response.get('type') == 'x3dh_key_exchange' and bob_response.get('from') == 'Bob':
                bob_bundle = bob_response['bundle']
                print("Alice received Bob's X3DH bundle")
                
                # Perform X3DH as sender (Alice initiates)
                shared_key, ephemeral_public, used_prekey_id = self.x3dh_session.perform_x3dh_sender(
                    alice_identity_key,
                    bob_bundle,
                    alice_ephemeral_key
                )
                
                # Initialize Double Ratchet with X3DH derived key
                self.alice_session = DoubleRatchetSession()
                
                # Wait for Bob's DH public key to complete initialization
                dh_response = self.client_socket.recv(4096).decode()
                dh_message = json.loads(dh_response)
                
                if dh_message.get('type') == 'dh_public_key' and dh_message.get('from') == 'Bob':
                    bob_dh_public_bytes = b64decode(dh_message['dh_public_key'])
                    bob_dh_public_key = x25519.X25519PublicKey.from_public_bytes(bob_dh_public_bytes)
                    
                    # Now initialize Alice with the correct Bob DH public key
                    self.alice_session.init_alice_with_shared_key(shared_key, bob_dh_public_key)
                    print("Alice received Bob's DH public key and completed initialization")
                else:
                    # Fallback to using Bob's identity key (may not work for decryption)
                    bob_initial_public = x25519.X25519PublicKey.from_public_bytes(
                        b64decode(bob_bundle['identity_key'])
                    )
                    self.alice_session.init_alice_with_shared_key(shared_key, bob_initial_public)
                    print("Alice using Bob's identity key as fallback")
                
                self.session_initialized = True
                print("Alice: Double Ratchet session initialized with X3DH")
                
                # Save initial state
                self.save_session_state()
                
                return True
            else:
                print("Alice: Invalid X3DH response from Bob")
                return False
                
        except Exception as e:
            self.error_handler.handle_error(e, "perform_x3dh_key_exchange")
            print("Alice: X3DH key exchange failed")
            return False
                
    def fallback_key_exchange(self):
        """Fallback to simple key exchange if X3DH fails"""
        try:
            if not self.client_socket:
                print("Alice: No connection to server")
                return False
                
            # Generate Alice's key pair
            alice_private_key = x25519.X25519PrivateKey.generate()
            alice_public_key = alice_private_key.public_key()
            
            # Send Alice's public key
            alice_public_bytes = alice_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            key_message = {
                'type': 'simple_key_exchange',
                'from': self.client_id,
                'public_key': b64encode(alice_public_bytes).decode()
            }
            self.client_socket.send(json.dumps(key_message).encode())
            print("Alice sent public key (fallback mode)")
            
            # Receive Bob's public key
            response = self.client_socket.recv(4096).decode()
            bob_key_data = json.loads(response)
            
            if bob_key_data.get('type') == 'simple_key_exchange' and bob_key_data.get('from') == 'Bob':
                bob_public_bytes = b64decode(bob_key_data['public_key'])
                bob_public_key = x25519.X25519PublicKey.from_public_bytes(bob_public_bytes)
                print("Alice received Bob's public key (fallback mode)")
                
                # Initialize Double Ratchet session
                self.alice_session = DoubleRatchetSession()
                self.alice_session.init_alice(alice_private_key, bob_public_key)
                self.session_initialized = True
                
                print("Alice: Double Ratchet session initialized (fallback mode)")
                
                # Save initial state
                self.save_session_state()
                
                return True
            else:
                print("Alice: Invalid fallback key exchange response")
                return False
                
        except Exception as e:
            self.error_handler.handle_error(e, "fallback_key_exchange")
            return False
    
    def save_session_state(self):
        """Save current session state"""
        try:
            if self.alice_session and self.session_initialized:
                state_data = {
                    'client_id': self.client_id,
                    'ratchet_state': self.alice_session.get_state(),
                    'last_updated': int(time.time())
                }
                
                self.state_manager.save_state(self.client_id, state_data, self.state_password)
        except Exception as e:
            self.error_handler.handle_error(e, "save_session_state")
                
    def send_enhanced_message(self, plaintext_message):
        """Send message with enhanced format and error handling"""
        try:
            if not self.session_initialized or not self.alice_session:
                print("Alice: Session not initialized, cannot send message")
                return False
            
            if not self.client_socket:
                print("Alice: No connection to server")
                return False
            
            # Encrypt message with Double Ratchet
            header, ciphertext, mac, ad = self.alice_session.ratchet_encrypt(plaintext_message)
            
            # Create enhanced message format
            enhanced_message = self.message_handler.create_message(
                from_user=self.client_id,
                to_user="Bob",
                message_type=self.message_handler.MESSAGE_TYPES['TEXT'],
                header=header,
                ciphertext=ciphertext,
                mac=mac,
                ad=ad,
                plaintext_content=plaintext_message
            )
            
            # Serialize and send
            message_json = self.message_handler.serialize_message(enhanced_message)
            self.client_socket.send(message_json.encode())
            
            print(f"Alice sent encrypted message: '{plaintext_message}'")
            print(f"  Message ID: {enhanced_message['message_id']}")
            print(f"  Sequence: {enhanced_message['sequence_number']}")
            
            # Save state after sending
            self.save_session_state()
            
            return True
            
        except Exception as e:
            self.error_handler.handle_error(e, "send_enhanced_message")
            return False
    
    def receive_messages(self):
        """Receive and handle messages from server"""
        try:
            if not self.client_socket:
                print("Alice: No connection to server")
                return False
                
            self.client_socket.settimeout(2)  # Non-blocking receive with timeout
            
            try:
                data = self.client_socket.recv(8192)
                if not data:
                    return False
                
                message_json = data.decode()
                message = self.message_handler.deserialize_message(message_json)
                
                # Validate message
                valid, validation_msg = self.message_handler.validate_message(message)
                if not valid:
                    print(f"Alice: Invalid message received: {validation_msg}")
                    return False
                
                # Record message for replay protection
                self.message_handler.record_message(message)
                
                print(f"Alice received message from {message['from']}")
                print(f"  Message ID: {message['message_id']}")
                print(f"  Age: {self.message_handler.get_message_age(message):.1f}s")
                
                return True
                
            except socket.timeout:
                return False  # No message available, continue
                
        except Exception as e:
            self.error_handler.handle_error(e, "receive_messages")
            return False
    
    def run_session(self):
        """Run the main Alice session"""
        try:
            # Connect to server
            if not self.connect_to_server():
                return False
            
            # Load existing session or prepare for new one
            session_loaded = self.load_or_create_session()
            
            if not session_loaded:
                # Try X3DH key exchange first
                print("Alice: Attempting X3DH key exchange...")
                if not self.perform_x3dh_key_exchange():
                    print("Alice: X3DH failed, falling back to simple key exchange...")
                    if not self.fallback_key_exchange():
                        print("Alice: All key exchange methods failed")
                        return False
            
            # Interactive message sending
            print("\n" + "="*60)
            print("    ALICE - Interactive Message Sender")
            print("    Type messages to send to Bob")
            print("    Commands: 'quit' to exit, 'status' for session info")
            print("="*60)
            
            message_count = 0
            while True:
                try:
                    # Get user input
                    user_input = input(f"\nAlice (message {message_count + 1}): ").strip()
                    
                    # Handle special commands
                    if user_input.lower() in ['quit', 'exit', 'q']:
                        print("Alice: Ending session...")
                        break
                    elif user_input.lower() == 'status':
                        print(f"Alice: Session active, {message_count} messages sent")
                        continue
                    elif not user_input:
                        print("Alice: Empty message, please type something or 'quit' to exit")
                        continue
                    
                    # Send the user message
                    print(f"Alice sending: '{user_input}'")
                    
                    if self.send_enhanced_message(user_input):
                        message_count += 1
                        print(f"  ✅ Message sent successfully (#{message_count})")
                        
                        # Check for any responses
                        self.receive_messages()
                    else:
                        print(f"  ❌ Failed to send message")
                        
                except KeyboardInterrupt:
                    print("\nAlice: Session interrupted by user")
                    break
                except Exception as e:
                    self.error_handler.handle_error(e, "interactive_messaging")
                    print(f"Alice: Error during messaging: {e}")
            
            print(f"\nAlice: Session completed - {message_count} messages sent")
            
            # Show error statistics
            stats = self.error_handler.get_error_statistics()
            if stats['total_errors'] > 0:
                print(f"\nAlice Error Statistics:")
                for error_type, count in stats['error_counts'].items():
                    print(f"  {error_type}: {count}")
            else:
                print("\nAlice: No errors encountered during session")
            
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
        success = alice_client.run_session()
        if success:
            print("Alice session completed successfully")
        else:
            print("Alice session failed")
    except KeyboardInterrupt:
        print("\nAlice session interrupted by user")
    except Exception as e:
        print(f"Alice session error: {e}")

if __name__ == "__main__":
    main()