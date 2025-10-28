# enhanced_bob.py - Enhanced Bob client with all production-like features
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

class EnhancedBobClient:
    """Enhanced Bob client with all production-like features"""
    
    def __init__(self):
        self.error_handler = ErrorHandler()
        self.state_manager = StateManager(self.error_handler)
        self.message_handler = MessageHandler()
        self.x3dh_session = X3DHSession(self.error_handler)
        
        self.client_socket: Optional[socket.socket] = None
        self.bob_session: Optional[DoubleRatchetSession] = None
        self.session_initialized = False
        self.identity_key: Optional[x25519.X25519PrivateKey] = None
        self.peer_identity_key: Optional[x25519.X25519PublicKey] = None
        
        # Client configuration
        self.client_id = "Bob"
        self.server_host = 'localhost'
        self.server_port = 9999
        self.state_password = "bob_secure_password_456"
    
    def connect_to_server(self):
        """Connect to the server with error handling and retry"""
        def _connect():
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)  # 10 second timeout
            self.client_socket.connect((self.server_host, self.server_port))
            return True
        
        success, result, error_info = self.error_handler.retry_operation(_connect, max_retries=3)
        
        if success:
            print("Bob connected to server")
            return True
        else:
            print(f"Bob failed to connect: {error_info}")
            return False
    
    def load_or_create_session(self):
        """Load existing session or create new one"""
        try:
            # Try to load existing state
            if self.state_manager.state_exists(self.client_id):
                print("Bob: Loading existing session state...")
                state_data = self.state_manager.load_state(self.client_id, self.state_password)
                
                # Restore Double Ratchet session
                self.bob_session = DoubleRatchetSession()
                self.bob_session.restore_state(state_data['ratchet_state'])
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
                        self.peer_identity_key = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
                    except Exception:
                        self.peer_identity_key = None
                
                print("Bob: Session state restored successfully")
                return True
            else:
                print("Bob: No existing session found, will create new one")
                return False
                
        except Exception as e:
            self.error_handler.handle_error(e, "load_or_create_session")
            print("Bob: Failed to load existing session, will create new one")
            return False
    
    def respond_to_x3dh_key_exchange(self):
        """Respond to X3DH key exchange from Alice"""
        try:
            if not self.client_socket:
                print("Bob: No connection to server")
                return False
            
            # First, generate Bob's keys and send his bundle to the server
            # so the server knows Bob is available for key exchange
            if not self.identity_key:
                self.identity_key = self.x3dh_session.generate_identity_key()
            bob_identity_key = self.identity_key
            bob_prekey = self.x3dh_session.generate_prekey(1)
            
            # Create Bob's bundle
            bob_bundle = {
                'identity_key': b64encode(bob_identity_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )).decode(),
                'signed_prekey': bob_prekey.serialize_public(),
                'one_time_prekeys': []  # Empty for simplified demo
            }
            
            # Send Bob's bundle to server first
            initial_message = {
                'type': 'x3dh_key_exchange',
                'from': self.client_id,
                'bundle': bob_bundle
            }
            
            self.client_socket.send(json.dumps(initial_message).encode())
            print("Bob sent X3DH key bundle to server")
                
            # Now wait for Alice's X3DH bundle from the server
            response = self.client_socket.recv(8192).decode()
            alice_message = json.loads(response)
            
            if alice_message.get('type') == 'x3dh_key_exchange' and alice_message.get('from') == 'Alice':
                alice_bundle = alice_message['bundle']
                print("Bob received Alice's X3DH bundle")
                try:
                    alice_identity_bytes = b64decode(alice_bundle['identity_key'])
                    self.peer_identity_key = x25519.X25519PublicKey.from_public_bytes(alice_identity_bytes)
                except Exception:
                    self.peer_identity_key = None
                
                # Perform X3DH as receiver
                alice_identity_public = b64decode(alice_bundle['identity_key'])
                alice_ephemeral_public = b64decode(alice_bundle['ephemeral_key'])
                
                shared_key = self.x3dh_session.perform_x3dh_receiver(
                    bob_identity_key,
                    bob_prekey,
                    None,  # No one-time prekey used
                    alice_identity_public,
                    alice_ephemeral_public
                )
                
                # Initialize Double Ratchet with X3DH derived key
                self.bob_session = DoubleRatchetSession()
                self.bob_session.init_bob_with_shared_key(shared_key)
                
                # Get Bob's DH public key that was generated during init
                if self.bob_session.state and 'DHs' in self.bob_session.state:
                    bob_dh_public_key = self.bob_session.state['DHs'].public_key()
                    
                    # Send Bob's DH public key to Alice so she can complete her initialization
                    dh_key_message = {
                        'type': 'dh_public_key',
                        'from': self.client_id,
                        'to': 'Alice',
                        'dh_public_key': b64encode(bob_dh_public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )).decode()
                    }
                    self.client_socket.send(json.dumps(dh_key_message).encode())
                    print("Bob sent DH public key to Alice")
                
                self.session_initialized = True
                
                print("Bob: Double Ratchet session initialized with X3DH")
                
                # Save initial state
                self.save_session_state()
                
                return True
            else:
                print("Bob: Invalid X3DH message from Alice")
                return False
                
        except Exception as e:
            self.error_handler.handle_error(e, "respond_to_x3dh_key_exchange")
            return False
    
    def fallback_key_exchange(self):
        """Fallback to simple key exchange if X3DH fails"""
        try:
            if not self.client_socket:
                print("Bob: No connection to server")
                return False
            
            # Generate Bob's key pair first
            bob_private_key = x25519.X25519PrivateKey.generate()
            bob_public_key = bob_private_key.public_key()
            
            # Send Bob's public key to server first
            bob_public_bytes = bob_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            key_message = {
                'type': 'simple_key_exchange',
                'from': self.client_id,
                'public_key': b64encode(bob_public_bytes).decode()
            }
            self.client_socket.send(json.dumps(key_message).encode())
            print("Bob sent public key (fallback mode)")
                
            # Now wait for Alice's public key from server
            response = self.client_socket.recv(4096).decode()
            alice_key_data = json.loads(response)
            
            if alice_key_data.get('type') == 'simple_key_exchange' and alice_key_data.get('from') == 'Alice':
                alice_public_bytes = b64decode(alice_key_data['public_key'])
                alice_public_key = x25519.X25519PublicKey.from_public_bytes(alice_public_bytes)
                print("Bob received Alice's public key (fallback mode)")
                
                # Initialize Double Ratchet session
                self.bob_session = DoubleRatchetSession()
                self.bob_session.init_bob()
                # Set Alice's public key when we receive first message
                self.alice_public_key = alice_public_key
                self.session_initialized = True
                
                print("Bob: Double Ratchet session initialized (fallback mode)")
                
                # Save initial state
                self.save_session_state()
                
                return True
            else:
                print("Bob: Invalid fallback key exchange message")
                return False
                
        except Exception as e:
            self.error_handler.handle_error(e, "fallback_key_exchange")
            return False
    
    def save_session_state(self):
        """Save current session state"""
        try:
            if self.bob_session and self.session_initialized:
                state_data = {
                    'client_id': self.client_id,
                    'ratchet_state': self.bob_session.get_state(),
                    'last_updated': int(time.time())
                }

                sealed_state = {}
                if self.identity_key:
                    sealed_state['identity_private'] = b64encode(self.identity_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )).decode()
                if self.peer_identity_key:
                    sealed_state['peer_identity_public'] = b64encode(self.peer_identity_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )).decode()
                if sealed_state:
                    state_data['sealed_sender'] = sealed_state
                
                self.state_manager.save_state(self.client_id, state_data, self.state_password)
                
                # Create backup
                backup_path = self.state_manager.create_backup(self.client_id, self.state_password)
                if backup_path:
                    print(f"Bob: Session backup created at {backup_path}")
                
        except Exception as e:
            self.error_handler.handle_error(e, "save_session_state")
    
    def receive_and_decrypt_messages(self):
        """Receive and decrypt messages from Alice"""
        try:
            if not self.client_socket:
                print("Bob: No connection to server")
                return False
                
            received_count = 0
            
            while True:
                try:
                    self.client_socket.settimeout(5)  # 5 second timeout
                    data = self.client_socket.recv(8192)
                    
                    if not data:
                        break
                    
                    message_json = data.decode()
                    message = self.message_handler.deserialize_message(message_json)
                    
                    # Validate message
                    valid, validation_msg = self.message_handler.validate_message(message)
                    if not valid:
                        print(f"Bob: Invalid message received: {validation_msg}")
                        continue
                    
                    # Record message for replay protection
                    self.message_handler.record_message(message)
                    sealed_sender = message.get('sealed_sender')
                    sender_label = message.get('from', 'Unknown')
                    if sealed_sender and self.identity_key:
                        try:
                            envelope = self.message_handler.open_sealed_sender_envelope(sealed_sender, self.identity_key)
                            sender_label = envelope.get('sender_id', sender_label)
                        except Exception as envelope_error:
                            sender_label = f"Sealed sender error: {envelope_error}"
                    
                    print(f"Bob received message from {sender_label}")
                    print(f"  Message ID: {message['message_id']}")
                    print(f"  Age: {self.message_handler.get_message_age(message):.1f}s")
                    
                    # Extract Double Ratchet components
                    components = self.message_handler.extract_double_ratchet_components(message)
                    
                    # Handle first message initialization for fallback mode
                    if not self.session_initialized and hasattr(self, 'alice_public_key') and self.bob_session:
                        if components['header'] and self.bob_session.state:
                            # Initialize receiver with Alice's DH key from first message
                            alice_dh_key = x25519.X25519PublicKey.from_public_bytes(components['header'].dh)
                            self.bob_session.state['DHr'] = alice_dh_key
                    
                    # Decrypt message
                    if self.session_initialized and self.bob_session and components['header']:
                        try:
                            plaintext = self.bob_session.ratchet_decrypt(
                                components['header'],
                                components['ciphertext'],
                                components['mac'],
                                components['ad']
                            )
                            
                            print(f"  Decrypted: '{plaintext}'")
                            received_count += 1
                            
                            # Save state after successful decryption
                            self.save_session_state()
                            
                        except Exception as decrypt_error:
                            print(f"  Failed to decrypt: {decrypt_error}")
                    
                except socket.timeout:
                    break  # No more messages
                except Exception as e:
                    print(f"Bob: Error receiving message: {e}")
                    break
            
            print(f"\nBob: Successfully received and decrypted {received_count} messages")
            return received_count > 0
            
        except Exception as e:
            self.error_handler.handle_error(e, "receive_and_decrypt_messages")
            return False
    
    def run_session(self):
        """Run the main Bob session"""
        try:
            # Connect to server
            if not self.connect_to_server():
                return False
            
            # Load existing session or prepare for new one
            session_loaded = self.load_or_create_session()
            
            if not session_loaded:
                # Try X3DH key exchange first
                print("Bob: Waiting for X3DH key exchange...")
                if not self.respond_to_x3dh_key_exchange():
                    print("Bob: X3DH failed, falling back to simple key exchange...")
                    if not self.fallback_key_exchange():
                        print("Bob: All key exchange methods failed")
                        return False
            else:
                # Even with existing session, Bob needs to register with server for message delivery
                if not self.client_socket:
                    print("Bob: No connection to server for registration")
                    return False
                    
                print("Bob: Registering with server for message delivery...")
                registration_message = {
                    'type': 'client_registration',
                    'from': self.client_id,
                    'status': 'ready_for_messages'
                }
                self.client_socket.send(json.dumps(registration_message).encode())
                print("Bob: Registration sent to server")
            
            # Interactive message receiving
            print("\n" + "="*60)
            print("    BOB - Interactive Message Receiver")
            print("    Waiting for messages from Alice...")
            print("    Press Ctrl+C to exit")
            print("="*60)
            
            if not self.client_socket:
                print("Bob: No connection to server")
                return False
                
            received_count = 0
            
            try:
                while True:
                    try:
                        # Wait for messages with a longer timeout for interactivity
                        self.client_socket.settimeout(1.0)  # 1 second timeout for responsive UI
                        data = self.client_socket.recv(8192)
                        
                        if not data:
                            continue
                            
                        message_json = data.decode()
                        message = self.message_handler.deserialize_message(message_json)
                        
                        # Validate message
                        valid, validation_msg = self.message_handler.validate_message(message)
                        if not valid:
                            print(f"\n❌ Invalid message: {validation_msg}")
                            continue
                        
                        # Record message for replay protection
                        self.message_handler.record_message(message)
                        sealed_sender = message.get('sealed_sender')
                        sender_label = message.get('from', 'Unknown')
                        if sealed_sender and self.identity_key:
                            try:
                                envelope = self.message_handler.open_sealed_sender_envelope(sealed_sender, self.identity_key)
                                sender_label = envelope.get('sender_id', sender_label)
                            except Exception as envelope_error:
                                sender_label = f"Sealed sender error: {envelope_error}"
                        
                        print(f"\n📨 New message from {sender_label}:")
                        print(f"   Message ID: {message['message_id']}")
                        print(f"   Age: {self.message_handler.get_message_age(message):.1f}s")
                        
                        # Extract Double Ratchet components
                        components = self.message_handler.extract_double_ratchet_components(message)
                        
                        # Handle first message initialization for fallback mode
                        if not self.session_initialized and hasattr(self, 'alice_public_key') and self.bob_session:
                            if components['header'] and self.bob_session.state:
                                # Initialize receiver with Alice's DH key from first message
                                alice_dh_key = x25519.X25519PublicKey.from_public_bytes(components['header'].dh)
                                self.bob_session.state['DHr'] = alice_dh_key
                        
                        # Decrypt message
                        if self.session_initialized and self.bob_session and components['header']:
                            try:
                                plaintext = self.bob_session.ratchet_decrypt(
                                    components['header'],
                                    components['ciphertext'],
                                    components['mac'],
                                    components['ad']
                                )
                                
                                received_count += 1
                                print(f"   ✅ Decrypted #{received_count}: '{plaintext}'")
                                
                                # Save state after successful decryption
                                self.save_session_state()
                                
                            except Exception as decrypt_error:
                                print(f"   ❌ Decryption failed: {decrypt_error}")
                        else:
                            print(f"   ⚠️  Session not ready for decryption")
                        
                    except socket.timeout:
                        # Show a heartbeat every few seconds to indicate Bob is still listening
                        if received_count == 0:
                            print(".", end="", flush=True)
                        continue
                    except Exception as e:
                        print(f"\n❌ Error receiving message: {e}")
                        break
                        
            except KeyboardInterrupt:
                print(f"\n\nBob: Session ended by user")
                print(f"Total messages received and decrypted: {received_count}")
                return received_count > 0
            
            # Show error statistics
            stats = self.error_handler.get_error_statistics()
            if stats['total_errors'] > 0:
                print(f"\nBob Error Statistics:")
                for error_type, count in stats['error_counts'].items():
                    print(f"  {error_type}: {count}")
            else:
                print("\nBob: No errors encountered during session")
            
            return True
            
        except Exception as e:
            self.error_handler.handle_error(e, "run_session")
            return False
        
        finally:
            if self.client_socket:
                self.client_socket.close()
                print("Bob disconnected from server")

def main():
    bob_client = EnhancedBobClient()
    
    try:
        success = bob_client.run_session()
        if success:
            print("Bob session completed successfully")
        else:
            print("Bob session failed")
    except KeyboardInterrupt:
        print("\nBob session interrupted by user")
    except Exception as e:
        print(f"Bob session error: {e}")

if __name__ == "__main__":
    main()