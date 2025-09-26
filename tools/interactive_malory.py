#!/usr/bin/env python3
"""
Interactive Malory - Forward Secrecy Demonstration Tool
Allows Malory to attempt decryption with intercepted keys/messages
"""

import sys
import os
import json
import time
from datetime import datetime

# Add src to path for imports
project_root = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(project_root, 'src'))

try:
    from core.double_ratchet import DoubleRatchetSession, deserialize
    from utils.error_handler import ErrorHandler
    from security.x3dh_integration import X3DHSession
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running from the correct directory")
    sys.exit(1)

class InteractiveMalory:
    """Interactive Malory for forward secrecy demonstration"""
    
    def __init__(self):
        self.intercepted_messages = []
        self.compromised_keys = {}
        self.session_states = {}
        
    def load_intercepted_messages(self):
        """Load intercepted messages from log files"""
        try:
            # Check multiple possible locations
            project_root = os.path.dirname(os.path.dirname(__file__))
            log_paths = [
                'malory_logs/intercepted_messages.json',
                os.path.join(project_root, 'malory_logs/intercepted_messages.json'),
                'src/network/malory_logs/intercepted_messages.json',
                os.path.join(project_root, 'src/network/malory_logs/intercepted_messages.json'),
                '../malory_logs/intercepted_messages.json'
            ]
            
            messages_loaded = 0
            for log_path in log_paths:
                if os.path.exists(log_path):
                    try:
                        with open(log_path, 'r', encoding='utf-8') as f:
                            for line in f:
                                try:
                                    message = json.loads(line.strip())
                                    self.intercepted_messages.append(message)
                                    messages_loaded += 1
                                except json.JSONDecodeError:
                                    continue
                    except Exception as e:
                        print(f"  Error reading {log_path}: {e}")
                    break  # Only load from first found file
            
            print(f"Loaded {messages_loaded} intercepted messages")
            return messages_loaded
            
        except Exception as e:
            print(f"Error loading messages: {e}")
            return 0
    
    def display_messages(self):
        """Display all intercepted messages"""
        if not self.intercepted_messages:
            print("\nNo intercepted messages found.")
            print("Make sure Alice and Bob are exchanging messages with the server running.")
            return
        
        print("\n" + "="*80)
        print("           INTERCEPTED MESSAGES")
        print("="*80)
        
        for i, msg in enumerate(self.intercepted_messages):
            try:
                print(f"\n[{i+1}] Message ID: {msg.get('message_id', 'unknown')}")
                print(f"    From: {msg.get('from')} -> To: {msg.get('to')}")
                print(f"    Sequence: {msg.get('sequence_number', 'unknown')}")
                print(f"    Timestamp: {datetime.fromtimestamp(msg.get('timestamp', 0)).strftime('%H:%M:%S')}")
                
                header_data = msg.get('header', '')
                if isinstance(header_data, str) and len(header_data) > 60:
                    print(f"    Header: {header_data[:60]}...")
                else:
                    print(f"    Header: {header_data}")
                
                ciphertext_data = msg.get('ciphertext', '')
                if isinstance(ciphertext_data, str) and len(ciphertext_data) > 60:
                    print(f"    Ciphertext: {ciphertext_data[:60]}...")
                else:
                    print(f"    Ciphertext: {ciphertext_data}")
                
                mac_data = msg.get('mac', '')
                if isinstance(mac_data, str) and len(mac_data) > 40:
                    print(f"    MAC: {mac_data[:40]}...")
                else:
                    print(f"    MAC: {mac_data}")
                    
            except Exception as e:
                print(f"Error displaying message {i+1}: {e}")
    
    def attempt_decryption(self):
        """Interactive decryption attempt"""
        if not self.intercepted_messages:
            print("No messages to decrypt. Load messages first.")
            return
        
        self.display_messages()
        
        try:
            choice = input(f"\nSelect message to decrypt (1-{len(self.intercepted_messages)}): ")
            msg_index = int(choice) - 1
            
            if msg_index < 0 or msg_index >= len(self.intercepted_messages):
                print("Invalid message selection")
                return
            
            message = self.intercepted_messages[msg_index]
            print(f"\nSelected message {msg_index + 1}")
            print(f"From: {message.get('from')} -> To: {message.get('to')}")
            print(f"Sequence: {message.get('sequence_number')}")
            
            # Try to decrypt with provided key material
            self.try_decrypt_message(message)
            
        except ValueError:
            print("Invalid input. Please enter a number.")
        except Exception as e:
            print(f"Error during decryption attempt: {e}")
    
    def try_decrypt_message(self, message):
        """Attempt to decrypt a specific message"""
        print("\n" + "="*60)
        print("           DECRYPTION ATTEMPT")
        print("="*60)
        
        print("To decrypt this message, you need:")
        print("1. The message key used for this specific message")
        print("2. Or the Double Ratchet session state at time of encryption")
        
        method = input("\nChoose method:\n1) Provide message key directly\n2) Provide compromised session state\n3) Show message details only\nChoice (1-3): ")
        
        if method == "1":
            self.decrypt_with_message_key(message)
        elif method == "2":
            self.decrypt_with_session_state(message)
        elif method == "3":
            self.show_message_details(message)
        else:
            print("Invalid choice")
    
    def decrypt_with_message_key(self, message):
        """Attempt decryption with a provided message key"""
        print("\nDECRYPTION WITH MESSAGE KEY:")
        print("In a real scenario, you might obtain the message key through:")
        print("- Memory dumps")
        print("- Side-channel attacks")
        print("- Compromised device")
        
        key_input = input("\nEnter message key (hex): ").strip()
        
        if not key_input:
            print("No key provided")
            return
        
        try:
            # Convert hex to bytes
            message_key = bytes.fromhex(key_input)
            
            # Try to decrypt
            ciphertext = message.get('ciphertext', '')
            mac = message.get('mac', '')
            
            if not ciphertext or not mac:
                print("Missing ciphertext or MAC data")
                return
            
            # Decode from base64-like encoding
            ciphertext_bytes = deserialize(ciphertext)
            mac_bytes = deserialize(mac)
            
            print(f"Key length: {len(message_key)} bytes")
            print(f"Ciphertext length: {len(ciphertext_bytes)} bytes")
            
            # This is where actual decryption would happen
            print("\n>>> ATTEMPTING DECRYPTION...")
            print(">>> This would require implementing the exact AES-GCM decryption")
            print(">>> with the Double Ratchet protocol details...")
            
            # Simulate successful/failed decryption
            success = len(message_key) == 32  # Simulate success if key is right length
            
            if success:
                print(">>> SUCCESS: Message decrypted!")
                print(f">>> Plaintext: [Simulated decryption result]")
                print("\n*** IMPORTANT: This key is now BURNED ***")
                print("*** Due to forward secrecy, this key cannot decrypt future messages ***")
                print("*** Each message uses a new key derived from the ratchet ***")
            else:
                print(">>> FAILED: Decryption failed")
                print(">>> Wrong key, corrupted data, or authentication failure")
            
        except ValueError:
            print("Invalid hex input")
        except Exception as e:
            print(f"Decryption error: {e}")
    
    def decrypt_with_session_state(self, message):
        """Attempt decryption with compromised session state"""
        print("\nDECRYPTION WITH SESSION STATE:")
        print("This simulates having a snapshot of the Double Ratchet state")
        print("at the time this message was encrypted.")
        
        print(f"\nMessage details:")
        print(f"  Sequence number: {message.get('sequence_number')}")
        print(f"  From: {message.get('from')}")
        print(f"  Header: {message.get('header', '')[:100]}...")
        
        print("\n>>> ATTEMPTING STATE-BASED DECRYPTION...")
        print(">>> This would require:")
        print(">>> 1. Deserializing the Double Ratchet state")
        print(">>> 2. Finding the correct message key for this sequence number")
        print(">>> 3. Performing AES-GCM decryption")
        
        # Simulate the process
        print(">>> [SIMULATED] Loading compromised session state...")
        print(">>> [SIMULATED] Finding message key for sequence", message.get('sequence_number'))
        print(">>> [SIMULATED] Attempting decryption...")
        
        # Simulate result based on message properties
        simulate_success = message.get('sequence_number', 0) <= 2  # First few messages "succeed"
        
        if simulate_success:
            print(">>> SUCCESS: Message decrypted with compromised state!")
            print(f">>> Plaintext: [Simulated message content]")
            print("\n!!! FORWARD SECRECY DEMONSTRATION !!!")
            print("!!! This state is from BEFORE key ratcheting !!!")
            print("!!! Newer messages used DIFFERENT keys and CANNOT be decrypted !!!")
            print("!!! with this old state due to the ratcheting mechanism !!!")
        else:
            print(">>> FAILED: This message was sent AFTER key ratcheting")
            print(">>> The compromised state is too old to decrypt this message")
            print(">>> This demonstrates FORWARD SECRECY in action!")
    
    def show_message_details(self, message):
        """Show detailed message information"""
        print("\nDETAILED MESSAGE ANALYSIS:")
        print("="*50)
        
        for key, value in message.items():
            if isinstance(value, str) and len(value) > 100:
                print(f"{key:20}: {value[:100]}...")
            else:
                print(f"{key:20}: {value}")
        
        print("\n>>> CRYPTANALYSIS NOTES:")
        print(">>> - Header contains DH public key and message number")
        print(">>> - Ciphertext is AES-256-GCM encrypted")
        print(">>> - MAC provides authentication")
        print(">>> - Each message uses a unique key from the ratchet")
        print(">>> - Forward secrecy prevents decryption of future messages")
    
    def run_demo(self):
        """Run the interactive forward secrecy demonstration"""
        print("="*80)
        print("           MALORY'S INTERACTIVE CRYPTANALYSIS TOOL")
        print("               Forward Secrecy Demonstration")
        print("="*80)
        
        print("\nThis tool demonstrates Double Ratchet forward secrecy:")
        print("1. Compromised keys can decrypt past messages")
        print("2. Same keys CANNOT decrypt future messages due to ratcheting")
        print("3. Each message uses a new key derived from the previous one")
        
        while True:
            print("\n" + "-"*60)
            print("MALORY'S OPTIONS:")
            print("1. Load intercepted messages")
            print("2. Display intercepted messages")
            print("3. Attempt message decryption (DEMO)")
            print("4. Show forward secrecy explanation")
            print("5. Exit")
            
            try:
                choice = input("\nEnter choice (1-5): ").strip()
                
                if choice == "1":
                    count = self.load_intercepted_messages()
                    print(f"Loaded {count} messages for analysis")
                    
                elif choice == "2":
                    self.display_messages()
                    
                elif choice == "3":
                    self.attempt_decryption()
                    
                elif choice == "4":
                    self.show_forward_secrecy_explanation()
                    
                elif choice == "5":
                    print("\nExiting Malory's cryptanalysis tool...")
                    break
                    
                else:
                    print("Invalid choice. Please enter 1-5.")
                    
            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def show_forward_secrecy_explanation(self):
        """Explain forward secrecy concept"""
        print("\n" + "="*80)
        print("           FORWARD SECRECY EXPLANATION")
        print("="*80)
        
        print("""
WHAT IS FORWARD SECRECY?
------------------------
Forward secrecy means that compromising long-term keys or current session
state does NOT compromise the confidentiality of FUTURE communications.

HOW DOUBLE RATCHET PROVIDES FORWARD SECRECY:
--------------------------------------------
1. Each message is encrypted with a unique message key
2. Message keys are derived from a chain key using a one-way function (HKDF)
3. After deriving a message key, the chain key is "ratcheted" forward
4. Old chain keys and message keys are deleted
5. Even if an attacker gets the current state, they cannot decrypt future messages

DEMONSTRATION SCENARIO:
-----------------------
1. Alice and Bob exchange messages using Double Ratchet
2. Malory (you) intercepts all encrypted messages
3. At some point, Malory compromises a device and obtains:
   - Current session state
   - Current keys
4. Malory can decrypt messages encrypted BEFORE the compromise
5. Malory CANNOT decrypt messages encrypted AFTER the compromise
6. This is because new keys are derived that Malory doesn't have

WHY THIS MATTERS:
-----------------
- Past communications remain secure even after key compromise
- Limits the damage from security breaches
- Essential for secure messaging in hostile environments
- Used in Signal, WhatsApp, and other secure messaging apps

TRY THE DEMO:
-------------
1. Start server: python run.py server
2. Start Alice: python run.py alice
3. Start Bob: python run.py bob
4. Let them exchange a few messages
5. Use this tool to simulate key compromise and decryption attempts
        """)

def main():
    """Main entry point"""
    malory = InteractiveMalory()
    malory.run_demo()

if __name__ == "__main__":
    main()