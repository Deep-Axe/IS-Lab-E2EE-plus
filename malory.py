# malory.py - Malory with Double Ratchet Message Interception
import socket
import json
from base64 import b64decode, b64encode
from double_ratchet import deserialize, DECRYPT_DOUB_RATCH, CONCAT, Header

HOST = "127.0.0.1"
PORT = 5000

class Malory:
    def __init__(self):
        self.name = "Malory"
        self.intercepted_messages = []
        
    def intercept_messages(self):
        """Intercept all Double Ratchet messages stored on the server"""
        try:
            s = socket.socket()
            s.connect((HOST, PORT))
            
            msg_data = {
                "cmd": "spy_messages"
            }
            
            s.send(json.dumps(msg_data).encode())
            response = json.loads(s.recv(8192).decode())
            
            if response["status"] == "ok":
                all_messages = response["all_messages"]
                if not all_messages:
                    print("📪 No messages intercepted")
                else:
                    print(f"🕵️ Intercepted {len(all_messages)} Double Ratchet message(s):")
                    for i, msg in enumerate(all_messages):
                        # Parse the header to show DH key info
                        try:
                            header = Header.deserialize(msg["header"])
                            dh_key_preview = b64encode(header.dh[:8]).decode() + "..."
                            print(f"  Message {i+1}:")
                            print(f"    From: {msg['from']} → {msg['to']}")
                            print(f"    DH Key: {dh_key_preview}")
                            print(f"    Message Number: {header.n}")
                            print(f"    Previous Chain: {header.pn}")
                            print(f"    Ciphertext: {msg['ciphertext'][:32]}...")
                            print(f"    MAC: {msg['mac'][:32]}...")
                            print()
                        except:
                            print(f"  Message {i+1}: [Cannot parse header]")
                        
                    self.intercepted_messages = all_messages
            else:
                print(f"❌ Error intercepting messages: {response.get('error', 'Unknown error')}")
                
            s.close()
            
        except Exception as e:
            print(f"❌ Error intercepting messages: {e}")
    
    def try_decrypt_with_message_key(self, message_index, message_key_b64):
        """Try to decrypt a specific intercepted Double Ratchet message with a message key"""
        if message_index < 0 or message_index >= len(self.intercepted_messages):
            print(f"❌ Message index {message_index} not found")
            return
            
        msg = self.intercepted_messages[message_index]
        
        try:
            # Deserialize message components
            header = Header.deserialize(msg["header"])
            ciphertext = (deserialize(msg["ciphertext"]), deserialize(msg["mac"]))
            AD = deserialize(msg["ad"])
            message_key = b64decode(message_key_b64.encode())
            
            # Try to decrypt using the Double Ratchet decrypt function
            padded_plaintext = DECRYPT_DOUB_RATCH(message_key, ciphertext, CONCAT(AD, header))
            
            # Remove padding
            from cryptography.hazmat.primitives import padding
            unpadder = padding.PKCS7(256).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            print(f"🎉 SUCCESS! Decrypted Double Ratchet message {message_index + 1}:")
            print(f"   From: {msg['from']} → {msg['to']}")
            print(f"   Plaintext: {plaintext.decode()}")
            print(f"   DH Ratchet Step: {header.n}")
            print(f"   ⚠️ But this is just ONE message key - others remain secure!")
            
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            print(f"   Double Ratchet protects other messages even with this key!")
    
    def show_double_ratchet_security_demo(self):
        """Demonstrate Double Ratchet security properties"""
        print("\n" + "="*70)
        print("🛡️ DOUBLE RATCHET SECURITY DEMONSTRATION")
        print("="*70)
        print("Scenario: Malory intercepts all ciphertext and gets ONE message key")
        print()
        print("🔐 Double Ratchet Security Properties:")
        print("  ✅ Forward Secrecy: Past messages safe if key compromised")
        print("  ✅ Backward Secrecy: Future messages safe if key compromised") 
        print("  ✅ Self-Healing: New DH exchanges create independent key chains")
        print("  ✅ Message Isolation: Each message uses unique derived key")
        print()
        print("🕵️ Even with Alice/Bob's cooperation, Malory can only decrypt:")
        print("  - The specific message whose key was revealed")
        print("  - NOT previous messages (forward secrecy)")
        print("  - NOT future messages (backward secrecy)")
        print("  - NOT messages from DH ratchet steps (self-healing)")
        print("="*70 + "\n")
    
    def analyze_ratchet_structure(self):
        """Analyze the Double Ratchet message structure"""
        if not self.intercepted_messages:
            print("📪 No intercepted messages. Use 'intercept' first.")
            return
            
        print("🔬 Double Ratchet Message Analysis:")
        print("-" * 50)
        
        dh_keys = set()
        message_chains = {}
        
        for i, msg in enumerate(self.intercepted_messages):
            try:
                header = Header.deserialize(msg["header"])
                dh_key_b64 = b64encode(header.dh).decode()
                
                dh_keys.add(dh_key_b64)
                
                if dh_key_b64 not in message_chains:
                    message_chains[dh_key_b64] = []
                message_chains[dh_key_b64].append({
                    'index': i+1,
                    'n': header.n, 
                    'pn': header.pn,
                    'from': msg['from']
                })
            except:
                continue
                
        print(f"🔑 Unique DH Keys Detected: {len(dh_keys)}")
        print(f"📊 Message Chains: {len(message_chains)}")
        print()
        
        for j, (dh_key, chain) in enumerate(message_chains.items()):
            print(f"Chain {j+1} (DH Key: {dh_key[:16]}...):")
            for msg_info in sorted(chain, key=lambda x: x['n']):
                print(f"  Msg #{msg_info['index']}: n={msg_info['n']}, pn={msg_info['pn']} from {msg_info['from']}")
            print()
    
    def interactive_mode(self):
        """Interactive mode for Malory with Double Ratchet analysis"""
        print(f"🕵️ {self.name} - Double Ratchet Message Interceptor")
        print("Commands: intercept, list, decrypt <msg_index> <message_key_b64>,")
        print("          analyze, demo, quit")
        print("=" * 60)
        
        while True:
            try:
                cmd = input(f"{self.name}> ").strip()
                
                if cmd.lower() == "quit":
                    break
                elif cmd.lower() == "intercept":
                    self.intercept_messages()
                elif cmd.lower() == "demo":
                    self.show_double_ratchet_security_demo()
                elif cmd.lower() == "analyze":
                    self.analyze_ratchet_structure()
                elif cmd.lower() == "list":
                    if not self.intercepted_messages:
                        print("📪 No intercepted messages. Use 'intercept' first.")
                    else:
                        print(f"📋 Intercepted Double Ratchet Messages ({len(self.intercepted_messages)}):")
                        for i, msg in enumerate(self.intercepted_messages):
                            direction = f"{msg['from']} → {msg['to']}"
                            try:
                                header = Header.deserialize(msg["header"])
                                print(f"  {i+1}. {direction} (n={header.n}, pn={header.pn})")
                            except:
                                print(f"  {i+1}. {direction} [Cannot parse header]")
                elif cmd.startswith("decrypt "):
                    try:
                        parts = cmd.split()
                        if len(parts) != 3:
                            print("Usage: decrypt <message_index> <message_key_b64>")
                            continue
                        
                        msg_index = int(parts[1]) - 1  # Convert to 0-based index
                        message_key_b64 = parts[2]
                        self.try_decrypt_with_message_key(msg_index, message_key_b64)
                        
                    except ValueError:
                        print("❌ Invalid message index")
                else:
                    print("Commands: intercept, list, decrypt <msg_index> <key_b64>, analyze, demo, quit")
                    
            except KeyboardInterrupt:
                break
        
        print(f"👋 {self.name} stopped spying on Double Ratchet messages")

if __name__ == "__main__":
    malory = Malory()
    malory.interactive_mode()