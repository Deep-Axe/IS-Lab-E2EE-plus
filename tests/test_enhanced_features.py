# test_enhanced_features.py - Comprehensive test suite for enhanced Double Ratchet features
import os
import sys
import time
import json
import threading
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives import serialization

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

def test_imports():
    """Test that all enhanced modules can be imported"""
    print("Testing module imports...")
    
    try:
        from core.double_ratchet import DoubleRatchetSession, Header, RatchetEncrypt, RatchetDecrypt
        print("✅ double_ratchet imports successful")
    except Exception as e:
        print(f"❌ double_ratchet import failed: {e}")
        return False
    
    try:
        from utils.state_manager import StateManager
        print("✅ state_manager imports successful")
    except Exception as e:
        print(f"❌ state_manager import failed: {e}")
        return False
    
    try:
        from utils.message_handler import MessageHandler
        print("✅ message_handler imports successful")
    except Exception as e:
        print(f"❌ message_handler import failed: {e}")
        return False
    
    try:
        from utils.error_handler import ErrorHandler, ErrorCode, DoubleRatchetError
        print("✅ error_handler imports successful")
    except Exception as e:
        print(f"❌ error_handler import failed: {e}")
        return False
    
    try:
        from security.x3dh_integration import X3DHSession, PreKeyServer, X3DHPreKey
        print("✅ x3dh_integration imports successful")
    except Exception as e:
        print(f"❌ x3dh_integration import failed: {e}")
        return False
    
    return True

def test_double_ratchet_session():
    """Test DoubleRatchetSession functionality"""
    print("\nTesting DoubleRatchetSession...")
    
    try:
        from double_ratchet import DoubleRatchetSession
        from cryptography.hazmat.primitives.asymmetric import x25519
        
        # Create Alice and Bob sessions
        alice_session = DoubleRatchetSession()
        bob_session = DoubleRatchetSession()
        
        # Generate keys
        bob_private = x25519.X25519PrivateKey.generate()
        bob_public = bob_private.public_key()
        
        # Initialize sessions
        alice_session.init_alice(x25519.X25519PrivateKey.generate(), bob_public)
        bob_session.init_bob()
        
        print("✅ Session initialization successful")
        
        # Test message encryption/decryption
        test_message = "Hello from Alice to Bob!"
        
        header, ciphertext, mac, ad = alice_session.ratchet_encrypt(test_message)
        print("✅ Message encryption successful")
        
        # For Bob to decrypt, he needs Alice's DH key from the header
        if bob_session.state and header and alice_session.state:
            bob_session.state['DHr'] = alice_session.state['DHs'].public_key()
            
            try:
                decrypted = bob_session.ratchet_decrypt(header, ciphertext, mac, ad)
                if decrypted == test_message:
                    print("✅ Message decryption successful")
                else:
                    print(f"❌ Decryption mismatch: got '{decrypted}', expected '{test_message}'")
                    return False
            except Exception as e:
                print(f"❌ Message decryption failed: {e}")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ DoubleRatchetSession test failed: {e}")
        return False

def test_state_manager():
    """Test StateManager functionality"""
    print("\nTesting StateManager...")
    
    try:
        from state_manager import StateManager
        from error_handler import ErrorHandler
        
        error_handler = ErrorHandler()
        state_manager = StateManager(error_handler)
        
        # Test data
        test_user = "test_user"
        test_password = "test_password_123"
        test_data = {
            'client_id': test_user,
            'ratchet_state': {'test': 'data', 'number': 42},
            'last_updated': int(time.time())
        }
        
        # Test save state
        success = state_manager.save_state(test_user, test_data, test_password)
        if not success:
            print("❌ State save failed")
            return False
        print("✅ State save successful")
        
        # Test state exists
        if not state_manager.state_exists(test_user):
            print("❌ State existence check failed")
            return False
        print("✅ State existence check successful")
        
        # Test load state
        loaded_data = state_manager.load_state(test_user, test_password)
        if loaded_data != test_data:
            print(f"❌ State load mismatch: got {loaded_data}, expected {test_data}")
            return False
        print("✅ State load successful")
        
        # Test backup creation
        backup_path = state_manager.create_backup(test_user, test_password)
        if not backup_path or not os.path.exists(backup_path):
            print("❌ Backup creation failed")
            return False
        print("✅ Backup creation successful")
        
        # Cleanup
        state_manager.delete_state(test_user)
        if os.path.exists(backup_path):
            os.remove(backup_path)
        
        return True
        
    except Exception as e:
        print(f"❌ StateManager test failed: {e}")
        return False

def test_message_handler():
    """Test MessageHandler functionality"""
    print("\nTesting MessageHandler...")
    
    try:
        from message_handler import MessageHandler
        from double_ratchet import Header
        from cryptography.hazmat.primitives.asymmetric import x25519
        
        message_handler = MessageHandler()
        
        # Create test header
        dh_key = x25519.X25519PrivateKey.generate()
        header = Header(
            dh_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            5, 10
        )
        
        # Create enhanced message
        message = message_handler.create_message(
            from_user="Alice",
            to_user="Bob",
            message_type=message_handler.MESSAGE_TYPES['TEXT'],
            header=header,
            ciphertext="test_ciphertext",
            mac="test_mac",
            ad="test_ad",
            plaintext_content="Hello Bob!"
        )
        
        print("✅ Message creation successful")
        
        # Test message validation
        valid, validation_msg = message_handler.validate_message(message)
        if not valid:
            print(f"❌ Message validation failed: {validation_msg}")
            return False
        print("✅ Message validation successful")
        
        # Test serialization/deserialization
        serialized = message_handler.serialize_message(message)
        deserialized = message_handler.deserialize_message(serialized)
        
        if deserialized['message_id'] != message['message_id']:
            print("❌ Message serialization/deserialization failed")
            return False
        print("✅ Message serialization/deserialization successful")
        
        # Test replay protection
        message_handler.record_message(message)
        valid, validation_msg = message_handler.validate_message(message)
        if valid:
            print("❌ Replay protection failed - duplicate message accepted")
            return False
        print("✅ Replay protection successful")
        
        return True
        
    except Exception as e:
        print(f"❌ MessageHandler test failed: {e}")
        return False

def test_error_handler():
    """Test ErrorHandler functionality"""
    print("\nTesting ErrorHandler...")
    
    try:
        from error_handler import ErrorHandler, ErrorCode, DoubleRatchetError, create_crypto_error
        
        error_handler = ErrorHandler()
        
        # Test error creation
        test_error = create_crypto_error(
            ErrorCode.ENCRYPTION_FAILED,
            "Test encryption failure",
            {"detail": "test detail"}
        )
        
        # Test error handling
        error_info = error_handler.handle_error(test_error, "test_context")
        
        if error_info['error_code'] != ErrorCode.ENCRYPTION_FAILED.value:
            print("❌ Error handling failed")
            return False
        print("✅ Error handling successful")
        
        # Test safe execution
        def failing_operation():
            raise ValueError("Test error")
        
        success, result, error_info = error_handler.safe_execute(failing_operation)
        if success:
            print("❌ Safe execution should have failed")
            return False
        print("✅ Safe execution successful")
        
        # Test parameter validation
        try:
            error_handler.validate_parameter("test_param", None)
            print("❌ Parameter validation should have failed")
            return False
        except DoubleRatchetError:
            print("✅ Parameter validation successful")
        
        return True
        
    except Exception as e:
        print(f"❌ ErrorHandler test failed: {e}")
        return False

def test_x3dh_integration():
    """Test X3DH integration functionality"""
    print("\nTesting X3DH integration...")
    
    try:
        from x3dh_integration import X3DHSession, PreKeyServer, X3DHPreKey
        from error_handler import ErrorHandler
        
        error_handler = ErrorHandler()
        x3dh_session = X3DHSession(error_handler)
        
        # Test key generation
        identity_key = x3dh_session.generate_identity_key()
        print("✅ Identity key generation successful")
        
        prekey = x3dh_session.generate_prekey(1)
        print("✅ Prekey generation successful")
        
        # Test prekey bundle generation
        bundle = x3dh_session.generate_prekey_bundle(5)
        print("✅ Prekey bundle generation successful")
        
        # Test bundle serialization
        serialized_bundle = bundle.serialize_bundle()
        if 'identity_key' not in serialized_bundle:
            print("❌ Bundle serialization failed")
            return False
        print("✅ Bundle serialization successful")
        
        # Test prekey server
        prekey_server = PreKeyServer()
        
        # Upload bundle
        success = prekey_server.upload_bundle("Alice", serialized_bundle)
        if not success:
            print("❌ Bundle upload failed")
            return False
        print("✅ Bundle upload successful")
        
        # Fetch bundle
        fetched_bundle = prekey_server.fetch_bundle("Alice")
        if fetched_bundle['identity_key'] != serialized_bundle['identity_key']:
            print("❌ Bundle fetch failed")
            return False
        print("✅ Bundle fetch successful")
        
        return True
        
    except Exception as e:
        print(f"❌ X3DH integration test failed: {e}")
        return False

def run_all_tests():
    """Run all tests and provide summary"""
    print("=" * 60)
    print("    ENHANCED DOUBLE RATCHET FEATURE TESTS")
    print("=" * 60)
    
    tests = [
        ("Module Imports", test_imports),
        ("DoubleRatchetSession", test_double_ratchet_session),
        ("StateManager", test_state_manager),
        ("MessageHandler", test_message_handler),
        ("ErrorHandler", test_error_handler),
        ("X3DH Integration", test_x3dh_integration)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n--- Running {test_name} Test ---")
        try:
            result = test_func()
            results[test_name] = result
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("                TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name:20} : {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! Enhanced features are working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    return passed == total

def main():
    try:
        # Add cryptography import for test
        from cryptography.hazmat.primitives import serialization
        
        success = run_all_tests()
        sys.exit(0 if success else 1)
        
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Please install: pip install cryptography")
        sys.exit(1)
    except Exception as e:
        print(f"Test suite error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()