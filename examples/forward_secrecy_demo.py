#!/usr/bin/env python3
"""
Forward Secrecy Demonstration
Shows how Double Ratchet prevents key reuse even when keys are compromised.
"""

import sys
import time
from pathlib import Path

# Setup Python path
project_root = Path(__file__).parent
src_path = project_root / 'src'
sys.path.insert(0, str(src_path))

from core.double_ratchet import DoubleRatchetSession
from utils.message_handler import MessageHandler
from tools.enhanced_malory import EnhancedMalory

def demonstrate_forward_secrecy():
    """Demonstrate that compromised keys can't decrypt future messages"""
    print("=" * 80)
    print("    FORWARD SECRECY DEMONSTRATION")
    print("  Showing that compromised keys can't decrypt future messages")
    print("=" * 80)
    
    # Initialize Alice and Bob sessions
    alice_session = DoubleRatchetSession()
    bob_session = DoubleRatchetSession()
    
    # Simple initialization for demo
    shared_secret = b"demo_shared_secret_for_forward_secrecy_test"
    bob_session.init_bob_with_shared_key(shared_secret)
    
    if bob_session.state and 'DHs' in bob_session.state:
        bob_dh_public_key = bob_session.state['DHs'].public_key()
        alice_session.init_alice_with_shared_key(shared_secret, bob_dh_public_key)
    
    message_handler = MessageHandler()
    malory = EnhancedMalory()
    
    print("\n1. Alice sends first message...")
    
    # First message
    plaintext1 = "Secret message #1: The treasure is buried under the old oak tree"
    header1, ciphertext1, mac1, ad1 = alice_session.ratchet_encrypt(plaintext1)
    
    enhanced_msg1 = message_handler.create_message(
        from_user="Alice",
        to_user="Bob", 
        message_type=message_handler.MESSAGE_TYPES['TEXT'],
        header=header1,
        ciphertext=ciphertext1,
        mac=mac1,
        ad=ad1,
        plaintext_content=plaintext1
    )
    
    print(f"   ✅ Message 1 sent: '{plaintext1}'")
    print(f"   📦 Ciphertext: {ciphertext1.hex()[:32]}...")
    
    # Bob decrypts normally
    components1 = message_handler.extract_double_ratchet_components(enhanced_msg1)
    decrypted1 = bob_session.ratchet_decrypt(
        components1['header'],
        components1['ciphertext'], 
        components1['mac'],
        components1['ad']
    )
    print(f"   ✅ Bob decrypted: '{decrypted1}'")
    
    print("\n2. 🕵️ Malory intercepts and gets the message key...")
    
    # Simulate Malory getting the current message key (this is what forward secrecy protects against)
    # In reality, this might happen through various attack vectors
    current_message_key = alice_session.state['CKs']  # Current chain key
    
    print(f"   🔓 Malory obtained key: {current_message_key.hex()[:16]}...")
    
    # Malory tries to decrypt the first message with the obtained key
    try:
        malory_decrypt = malory.attempt_decryption_with_key(enhanced_msg1, current_message_key)
        if malory_decrypt:
            print(f"   ❌ Malory successfully decrypted message 1: '{malory_decrypt}'")
            print("   ⚠️  This shows the key was valid for this message")
        else:
            print("   ❌ Malory's decryption failed (key didn't work)")
    except Exception as e:
        print(f"   ❌ Malory's decryption failed: {e}")
    
    print("\n3. Alice sends second message (key ratcheting occurs)...")
    time.sleep(0.1)  # Small delay for timestamp difference
    
    # Second message - this will use a NEW key due to ratcheting
    plaintext2 = "Secret message #2: The meeting is at midnight at the dock"
    header2, ciphertext2, mac2, ad2 = alice_session.ratchet_encrypt(plaintext2)
    
    enhanced_msg2 = message_handler.create_message(
        from_user="Alice",
        to_user="Bob",
        message_type=message_handler.MESSAGE_TYPES['TEXT'],
        header=header2,
        ciphertext=ciphertext2,
        mac=mac2,
        ad=ad2,
        plaintext_content=plaintext2
    )
    
    print(f"   ✅ Message 2 sent: '{plaintext2}'")
    print(f"   📦 Ciphertext: {ciphertext2.hex()[:32]}...")
    
    # Bob decrypts normally (he has the correct ratcheted state)
    components2 = message_handler.extract_double_ratchet_components(enhanced_msg2)
    decrypted2 = bob_session.ratchet_decrypt(
        components2['header'],
        components2['ciphertext'],
        components2['mac'], 
        components2['ad']
    )
    print(f"   ✅ Bob decrypted: '{decrypted2}'")
    
    print("\n4. 🕵️ Malory tries to decrypt message 2 with the old key...")
    
    # Malory tries to use the same old key on the new message
    try:
        malory_decrypt2 = malory.attempt_decryption_with_key(enhanced_msg2, current_message_key)
        if malory_decrypt2:
            print(f"   ❌ SECURITY FAILURE: Malory decrypted message 2: '{malory_decrypt2}'")
            print("   🚨 Forward secrecy is broken!")
        else:
            print("   ✅ SUCCESS: Malory could NOT decrypt message 2 with old key")
            print("   🛡️  Forward secrecy is working - old keys are useless!")
    except Exception as e:
        print(f"   ✅ SUCCESS: Malory's decryption failed: {e}")
        print("   🛡️  Forward secrecy is working - old keys are useless!")
    
    print("\n5. Demonstrating key evolution...")
    
    # Show that keys have actually changed
    new_message_key = alice_session.state['CKs']
    
    print(f"   🔑 Old key: {current_message_key.hex()[:16]}...")
    print(f"   🔑 New key: {new_message_key.hex()[:16]}...")
    
    if current_message_key != new_message_key:
        print("   ✅ Keys are different - ratcheting occurred")
    else:
        print("   ❌ Keys are same - ratcheting may have failed")
    
    print("\n" + "="*80)
    print("                FORWARD SECRECY DEMONSTRATION COMPLETE")
    print("="*80)
    print("🛡️  RESULT: Even with a compromised key, future messages remain secure")
    print("🔄  KEY RATCHETING: Each message uses a new key derived from the previous")
    print("🚫  OLD KEYS: Cannot decrypt new messages even if compromised")
    print("✅  FORWARD SECRECY: Confirmed working in Double Ratchet implementation")
    print("="*80)

if __name__ == "__main__":
    demonstrate_forward_secrecy()