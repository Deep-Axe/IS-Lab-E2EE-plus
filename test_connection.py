#!/usr/bin/env python3
"""
Simple test script to debug the connection and key exchange process
"""
import socket
import json
import time
import sys

def test_alice_connection():
    """Test Alice's connection process"""
    print("Testing Alice connection...")
    
    try:
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(30)  # 30 second timeout
        client_socket.connect(('localhost', 9999))
        print("✓ Alice connected to server")
        
        # Send X3DH key exchange message
        test_bundle = {
            'identity_key': 'test_alice_identity',
            'ephemeral_key': 'test_alice_ephemeral'
        }
        
        message = {
            'type': 'x3dh_key_exchange',
            'from': 'Alice',
            'bundle': test_bundle
        }
        
        client_socket.send(json.dumps(message).encode())
        print("✓ Alice sent X3DH key bundle")
        
        # Wait for response (with longer timeout)
        print("Alice waiting for Bob's response...")
        start_time = time.time()
        
        while time.time() - start_time < 60:  # Wait up to 60 seconds
            try:
                client_socket.settimeout(5)  # Short timeout for individual recv
                response = client_socket.recv(8192)
                
                if response:
                    message = json.loads(response.decode())
                    print(f"✓ Alice received: {message.get('type')} from {message.get('from')}")
                    break
                else:
                    print("Empty response, continuing...")
                    
            except socket.timeout:
                print(".", end="", flush=True)
                continue
            except Exception as e:
                print(f"Error receiving: {e}")
                break
        
        client_socket.close()
        print("\nAlice connection test completed")
        
    except Exception as e:
        print(f"Alice connection failed: {e}")

def test_bob_connection():
    """Test Bob's connection process"""
    print("Testing Bob connection...")
    
    try:
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(30)
        client_socket.connect(('localhost', 9999))
        print("✓ Bob connected to server")
        
        # Wait for Alice's bundle first
        print("Bob waiting for Alice's X3DH bundle...")
        response = client_socket.recv(8192)
        alice_message = json.loads(response.decode())
        
        if alice_message.get('type') == 'x3dh_key_exchange':
            print(f"✓ Bob received Alice's bundle: {alice_message.get('from')}")
            
            # Send response
            bob_bundle = {
                'identity_key': 'test_bob_identity',
                'signed_prekey': 'test_bob_prekey'
            }
            
            response_message = {
                'type': 'x3dh_key_exchange',
                'from': 'Bob',
                'bundle': bob_bundle
            }
            
            client_socket.send(json.dumps(response_message).encode())
            print("✓ Bob sent response bundle")
        
        client_socket.close()
        print("Bob connection test completed")
        
    except Exception as e:
        print(f"Bob connection failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "alice":
            test_alice_connection()
        elif sys.argv[1] == "bob":
            test_bob_connection()
        else:
            print("Usage: python test_connection.py [alice|bob]")
    else:
        print("Usage: python test_connection.py [alice|bob]")
        print("Run 'alice' first, then 'bob' in a separate terminal")