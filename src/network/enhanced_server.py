# enhanced_server.py - Enhanced server with message relay and X3DH support
import socket
import threading
import json
import time

# Use absolute imports that work both standalone and as package
try:
    from utils.error_handler import ErrorHandler, ErrorCode, create_network_error
except ImportError:
    # Fallback for when run as script
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from utils.error_handler import ErrorHandler, ErrorCode, create_network_error

class EnhancedServer:
    """Enhanced server with message relay and key exchange support"""
    
    def __init__(self, host='localhost', port=9999):
        self.host = host
        self.port = port
        self.error_handler = ErrorHandler()
        self.clients = {}  # client_id -> (socket, address, status)
        self.message_queue = {}  # client_id -> [messages]
        self.key_bundles = {}  # client_id -> key_bundle
        
        # Server state
        self.running = False
        self.server_socket = None
        
    def start_server(self):
        """Start the enhanced server"""
        try:
            # Fix socket configuration - use correct address family and socket type
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            
            self.running = True
            print(f"Enhanced Double Ratchet Server started on {self.host}:{self.port}")
            print("Features: Message relay, X3DH support, enhanced error handling")
            print("Waiting for Alice and Bob connections...\n")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"New connection from {address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:  # Only log if server is supposed to be running
                        self.error_handler.handle_error(e, "accept_connection")
            
        except Exception as e:
            self.error_handler.handle_error(e, "start_server")
        finally:
            self.stop_server()
    
    def handle_client(self, client_socket, address):
        """Handle individual client connections"""
        client_id = None
        
        try:
            while self.running:
                try:
                    # Set timeout to avoid blocking forever
                    client_socket.settimeout(30)
                    data = client_socket.recv(8192)
                    
                    if not data:
                        break
                    
                    message = json.loads(data.decode())
                    message_type = message.get('type')
                    
                    # Handle different message types
                    if message_type == 'x3dh_key_exchange':
                        client_id = message.get('from')
                        self.handle_x3dh_key_exchange(message, client_socket, address)
                    
                    elif message_type == 'simple_key_exchange':
                        client_id = message.get('from')
                        self.handle_simple_key_exchange(message, client_socket, address)
                    
                    elif message_type == 'dh_public_key':
                        # Forward DH public key to recipient
                        self.handle_dh_key_message(message, client_socket)
                    
                    elif message_type == 'client_registration':
                        # Handle client registration for existing sessions
                        client_id = message.get('from')
                        self.handle_client_registration(message, client_socket, address)
                    
                    else:
                        # Regular encrypted message
                        self.handle_encrypted_message(message, client_socket)
                    
                except socket.timeout:
                    continue  # Continue waiting for messages
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON from {address}: {e}")
                    continue
                except Exception as e:
                    self.error_handler.handle_error(e, f"handle_client_{address}")
                    break
                    
        except Exception as e:
            self.error_handler.handle_error(e, f"client_handler_{address}")
        finally:
            # Clean up client
            if client_id and client_id in self.clients:
                del self.clients[client_id]
                print(f"{client_id} disconnected")
            client_socket.close()
    
    def handle_x3dh_key_exchange(self, message, client_socket, address):
        """Handle X3DH key exchange messages with proper state management"""
        try:
            client_id = message['from']
            key_bundle = message['bundle']
            
            print(f"{client_id} sent X3DH key bundle")
            
            # Register/update client
            self.clients[client_id] = (client_socket, address, 'x3dh_waiting')
            self.key_bundles[client_id] = key_bundle
            
            # Check if both Alice and Bob are connected
            alice_connected = 'Alice' in self.clients
            bob_connected = 'Bob' in self.clients
            
            if alice_connected and bob_connected:
                print("Both Alice and Bob connected, initiating X3DH key exchange...")
                
                # Send Alice's bundle to Bob
                alice_bundle_msg = {
                    'type': 'x3dh_key_exchange',
                    'from': 'Alice',
                    'bundle': self.key_bundles['Alice']
                }
                bob_socket = self.clients['Bob'][0]
                bob_socket.send(json.dumps(alice_bundle_msg).encode())
                print("Sent Alice's bundle to Bob")
                
                # Send Bob's bundle to Alice
                bob_bundle_msg = {
                    'type': 'x3dh_key_exchange', 
                    'from': 'Bob',
                    'bundle': self.key_bundles['Bob']
                }
                alice_socket = self.clients['Alice'][0]
                alice_socket.send(json.dumps(bob_bundle_msg).encode())
                print("Sent Bob's bundle to Alice")
                
                # Mark both clients as ready
                self.clients['Alice'] = (*self.clients['Alice'][:2], 'ready')
                self.clients['Bob'] = (*self.clients['Bob'][:2], 'ready')
                
                print("X3DH key exchange completed - both clients ready for messaging")
            else:
                if client_id == 'Alice':
                    print("Alice registered, waiting for Bob...")
                else:
                    print("Bob registered, waiting for Alice...")
            
        except Exception as e:
            self.error_handler.handle_error(e, "handle_x3dh_key_exchange")
    
    def handle_simple_key_exchange(self, message, client_socket, address):
        """Handle simple key exchange messages with proper state management"""
        try:
            client_id = message['from']
            
            print(f"{client_id} sent simple key exchange")
            
            # Register/update client
            self.clients[client_id] = (client_socket, address, 'simple_waiting')
            self.key_bundles[client_id] = message
            
            # Check if both Alice and Bob are connected
            alice_connected = 'Alice' in self.clients
            bob_connected = 'Bob' in self.clients
            
            if alice_connected and bob_connected:
                print("Both Alice and Bob connected, exchanging simple keys...")
                
                # Send Alice's key to Bob
                alice_message = self.key_bundles['Alice']
                bob_socket = self.clients['Bob'][0]
                bob_socket.send(json.dumps(alice_message).encode())
                print("Sent Alice's key to Bob")
                
                # Send Bob's key to Alice  
                bob_message = self.key_bundles['Bob']
                alice_socket = self.clients['Alice'][0]
                alice_socket.send(json.dumps(bob_message).encode())
                print("Sent Bob's key to Alice")
                
                # Mark both clients as ready
                self.clients['Alice'] = (*self.clients['Alice'][:2], 'ready')
                self.clients['Bob'] = (*self.clients['Bob'][:2], 'ready')
                
                print("Simple key exchange completed - both clients ready for messaging")
            else:
                if client_id == 'Alice':
                    print("Alice registered, waiting for Bob...")
                else:
                    print("Bob registered, waiting for Alice...")
            
        except Exception as e:
            self.error_handler.handle_error(e, "handle_simple_key_exchange")
    
    def handle_dh_key_message(self, message, client_socket):
        """Handle DH public key exchange for Double Ratchet initialization"""
        try:
            from_user = message.get('from')
            to_user = message.get('to')
            
            print(f"Relaying DH public key from {from_user} to {to_user}")
            
            # Forward message to recipient
            if to_user in self.clients:
                recipient_socket = self.clients[to_user][0]
                recipient_socket.send(json.dumps(message).encode())
                print(f"DH public key relayed to {to_user}")
            else:
                print(f"Recipient {to_user} not connected for DH key exchange")
            
        except Exception as e:
            self.error_handler.handle_error(e, "handle_dh_key_message")
    
    def handle_client_registration(self, message, client_socket, address):
        """Handle client registration for existing sessions"""
        try:
            client_id = message.get('from')
            status = message.get('status', 'ready')
            
            print(f"{client_id} registered for message delivery (status: {status})")
            
            # Register client as ready for messages
            self.clients[client_id] = (client_socket, address, 'ready')
            
            # If there are queued messages for this client, deliver them
            if client_id in self.message_queue:
                queued_messages = self.message_queue[client_id]
                print(f"Delivering {len(queued_messages)} queued messages to {client_id}")
                
                for queued_msg in queued_messages:
                    try:
                        client_socket.send(json.dumps(queued_msg).encode())
                        print(f"  Delivered queued message {queued_msg.get('message_id', 'unknown')}")
                    except Exception as e:
                        print(f"  Failed to deliver queued message: {e}")
                        break
                
                # Clear the queue after delivery
                del self.message_queue[client_id]
                print(f"Message queue cleared for {client_id}")
            
        except Exception as e:
            self.error_handler.handle_error(e, "handle_client_registration")
    
    def handle_encrypted_message(self, message, client_socket):
        """Handle encrypted messages between clients"""
        try:
            from_user = message.get('from')
            to_user = message.get('to')
            
            if not from_user or not to_user:
                print("Invalid message: missing from or to field")
                return
            
            print(f"Relaying encrypted message from {from_user} to {to_user}")
            print(f"  Message ID: {message.get('message_id', 'unknown')}")
            print(f"  Sequence: {message.get('sequence_number', 'unknown')}")
            print(f"  Size: {len(json.dumps(message))} bytes")
            
            # Forward message to recipient
            if to_user in self.clients:
                recipient_socket = self.clients[to_user][0]
                try:
                    recipient_socket.send(json.dumps(message).encode())
                    print(f"  Successfully relayed to {to_user}")
                except Exception as e:
                    print(f"  Failed to relay to {to_user}: {e}")
            else:
                print(f"  Recipient {to_user} not connected")
                
                # Store message for later delivery (simple queue)
                if to_user not in self.message_queue:
                    self.message_queue[to_user] = []
                self.message_queue[to_user].append(message)
                print(f"  Message queued for {to_user}")
            
            # Log for Malory (cryptanalysis)
            self.log_for_malory(message)
            
        except Exception as e:
            self.error_handler.handle_error(e, "handle_encrypted_message")
    
    def log_for_malory(self, message):
        """Log encrypted messages for Malory's cryptanalysis"""
        try:
            log_entry = {
                'timestamp': int(time.time()),
                'from': message.get('from'),
                'to': message.get('to'),
                'message_id': message.get('message_id'),
                'sequence_number': message.get('sequence_number'),
                'header': message.get('header'),
                'ciphertext': message.get('ciphertext'),
                'mac': message.get('mac'),
                'ad': message.get('ad'),
                'metadata': message.get('metadata', {})
            }
            
            # Print key information for Malory's cryptanalysis demo
            print("=" * 60)
            print("MALORY'S KEY INTERCEPTION LOG")
            print("=" * 60)
            print(f"Message ID: {message.get('message_id', 'unknown')}")
            print(f"From: {message.get('from')} -> To: {message.get('to')}")
            print(f"Sequence: {message.get('sequence_number', 'unknown')}")
            print(f"Timestamp: {time.strftime('%H:%M:%S', time.localtime())}")
            
            # Extract and display header information for key analysis
            header_data = message.get('header')
            if header_data:
                print(f"Header (DH Key Info): {header_data[:100]}..." if len(header_data) > 100 else header_data)
            
            # Show first part of ciphertext for analysis
            ciphertext_data = message.get('ciphertext', '')
            if ciphertext_data:
                print(f"Ciphertext Sample: {ciphertext_data[:100]}..." if len(ciphertext_data) > 100 else ciphertext_data)
            
            # MAC for integrity verification
            mac_data = message.get('mac', '')
            if mac_data:
                print(f"MAC: {mac_data[:50]}..." if len(mac_data) > 50 else mac_data)
            
            print("Status: Message intercepted and logged for cryptanalysis")
            print("WARNING: Forward secrecy means old keys won't decrypt new messages!")
            print("=" * 60)
            
            # Append to Malory's log file
            import os
            os.makedirs('malory_logs', exist_ok=True)
            
            with open('malory_logs/intercepted_messages.json', 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            # Also log to a human-readable format for demo
            with open('malory_logs/malory_analysis.txt', 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"MALORY'S INTERCEPTION LOG - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*60}\n")
                f.write(f"Message ID: {message.get('message_id', 'unknown')}\n")
                f.write(f"From: {message.get('from')} -> To: {message.get('to')}\n")
                f.write(f"Sequence: {message.get('sequence_number', 'unknown')}\n")
                f.write(f"Header: {header_data}\n")
                f.write(f"Ciphertext: {ciphertext_data}\n")
                f.write(f"MAC: {mac_data}\n")
                f.write("Status: Intercepted for cryptanalysis attempt\n")
                f.write("Note: Double Ratchet forward secrecy should prevent decryption of future messages\n")
                f.write(f"{'='*60}\n\n")
            
        except Exception as e:
            # Don't let logging errors affect message relay
            self.error_handler.handle_error(e, "log_for_malory")
    
    def get_server_stats(self):
        """Get server statistics"""
        return {
            'connected_clients': len(self.clients),
            'client_list': list(self.clients.keys()),
            'queued_messages': {user: len(messages) for user, messages in self.message_queue.items()},
            'key_bundles': list(self.key_bundles.keys()),
            'error_stats': self.error_handler.get_error_statistics()
        }
    
    def stop_server(self):
        """Stop the server gracefully"""
        print("\nStopping Enhanced Double Ratchet Server...")
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
        
        # Close all client connections
        for client_id, (client_socket, address, status) in self.clients.items():
            client_socket.close()
            print(f"Closed connection to {client_id}")
        
        # Show final statistics
        stats = self.get_server_stats()
        print(f"\nFinal Server Statistics:")
        print(f"  Total clients served: {len(self.key_bundles)}")
        if stats['error_stats']['total_errors'] > 0:
            print(f"  Total errors: {stats['error_stats']['total_errors']}")
            for error_type, count in stats['error_stats']['error_counts'].items():
                print(f"    {error_type}: {count}")
        else:
            print("  No errors encountered")
        
        print("Server stopped successfully")

def main():
    server = EnhancedServer()
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server.stop_server()

if __name__ == "__main__":
    main()