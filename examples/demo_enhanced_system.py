# demo_enhanced_system.py - Comprehensive demonstration of all enhanced features
import os
import sys
import time
import threading
import subprocess
from pathlib import Path

# Setup Python path for module imports
project_root = Path(__file__).parent.parent
src_path = project_root / 'src'
sys.path.insert(0, str(src_path))

def print_banner():
    print("=" * 80)
    print("         ENHANCED DOUBLE RATCHET DEMONSTRATION")
    print("    Production-like features for educational purposes")
    print("=" * 80)
    print()

def print_section(title):
    print("\n" + "-" * 60)
    print(f"  {title}")
    print("-" * 60)

def demonstrate_core_features():
    """Demonstrate core enhanced features without networking"""
    print_section("CORE ENHANCED FEATURES DEMONSTRATION")
    
    try:
        # Import all modules with proper path handling for linter
        import sys
        import os
        from pathlib import Path
        
        # Ensure src is in path for imports
        project_root = Path(__file__).parent.parent
        src_path = project_root / 'src'
        if str(src_path) not in sys.path:
            sys.path.insert(0, str(src_path))
        
        # Now import modules - these should work both at runtime and for linter
        try:
            from core.double_ratchet import DoubleRatchetSession  # type: ignore
            from utils.state_manager import StateManager  # type: ignore
            from utils.message_handler import MessageHandler  # type: ignore
            from utils.error_handler import ErrorHandler  # type: ignore
            from security.x3dh_integration import X3DHSession  # type: ignore
        except ImportError as e:
            # Fallback: try importing from parent directory structure
            sys.path.insert(0, str(project_root))
            from src.core.double_ratchet import DoubleRatchetSession  # type: ignore
            from src.utils.state_manager import StateManager  # type: ignore
            from src.utils.message_handler import MessageHandler  # type: ignore
            from src.utils.error_handler import ErrorHandler  # type: ignore
            from src.security.x3dh_integration import X3DHSession  # type: ignore
            
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization
        
        print("1. Initializing enhanced components...")
        
        # Initialize components
        error_handler = ErrorHandler()
        state_manager = StateManager(error_handler)
        message_handler = MessageHandler()
        x3dh_session = X3DHSession(error_handler)
        
        print("   All components initialized successfully")
        
        print("\n2. Demonstrating X3DH key exchange...")
        
        # Generate Alice's keys
        alice_identity = x3dh_session.generate_identity_key()
        alice_ephemeral = x25519.X25519PrivateKey.generate()
        
        # Generate Bob's bundle
        bob_bundle = x3dh_session.generate_prekey_bundle(3)
        bob_serialized = bob_bundle.serialize_bundle()
        
        # Perform X3DH
        shared_key, ephemeral_public, used_prekey_id = x3dh_session.perform_x3dh_sender(
            alice_identity,
            bob_serialized,
            alice_ephemeral
        )
        
        print(f"    X3DH key exchange completed")
        print(f"    Shared key derived: {len(shared_key)} bytes")
        print(f"    Used prekey ID: {used_prekey_id}")
        
        print("\n3. Demonstrating Double Ratchet with X3DH key...")
        
        # Initialize Double Ratchet with X3DH shared key using working pattern
        alice_session = DoubleRatchetSession()
        bob_session = DoubleRatchetSession()
        
        # Initialize Bob first (receiver) with shared key
        bob_session.init_bob_with_shared_key(shared_key)
        
        # Alice needs Bob's DH public key for initialization
        if bob_session.state and 'DHs' in bob_session.state:
            bob_dh_public_key = bob_session.state['DHs'].public_key()
            alice_session.init_alice_with_shared_key(shared_key, bob_dh_public_key)
            print("    Double Ratchet sessions initialized with X3DH key")
        else:
            # Fallback to simple shared secret demo
            print("     Using fallback shared secret initialization")
            alice_session.init_alice_with_shared_key(shared_key, bob_bundle.identity_key.public_key())
            bob_session.init_bob_with_shared_key(shared_key)
            print("    Double Ratchet sessions initialized with X3DH key")
        
        print("\n4. Demonstrating enhanced message format...")
        
        # Create and encrypt message
        test_messages = [
            "Hello Bob! This is an enhanced Double Ratchet message.",
            "This message includes versioning and replay protection.",
            "All cryptographic operations use production-grade primitives."
        ]
        
        encrypted_messages = []
        
        for i, plaintext in enumerate(test_messages):
            # Add small delay to ensure timestamp differences
            if i > 0:
                time.sleep(0.01)  # 10ms delay
                
            header, ciphertext, mac, ad = alice_session.ratchet_encrypt(plaintext)
            
            # Create enhanced message format
            enhanced_message = message_handler.create_message(
                from_user="Alice",
                to_user="Bob",
                message_type=message_handler.MESSAGE_TYPES['TEXT'],
                header=header,
                ciphertext=ciphertext,
                mac=mac,
                ad=ad,
                plaintext_content=plaintext
            )
            
            encrypted_messages.append((enhanced_message, plaintext))
            print(f"    Message {i+1} encrypted and formatted")
            print(f"      Message ID: {enhanced_message['message_id']}")
            print(f"      Sequence: {enhanced_message['sequence_number']}")
        
        print("\n5. Demonstrating message validation and decryption...")
        
        # Bob's message handler for validation
        bob_message_handler = MessageHandler()
        
        for i, (enhanced_message, original_plaintext) in enumerate(encrypted_messages):
            # Validate message
            valid, validation_msg = bob_message_handler.validate_message(enhanced_message)
            if not valid:
                print(f"    Message {i+1} validation failed: {validation_msg}")
                continue
            
            # Record for replay protection
            bob_message_handler.record_message(enhanced_message)
            
            # Extract Double Ratchet components
            components = bob_message_handler.extract_double_ratchet_components(enhanced_message)
            
            # Decrypt
            try:
                decrypted = bob_session.ratchet_decrypt(
                    components['header'],
                    components['ciphertext'],
                    components['mac'],
                    components['ad']
                )
                
                if decrypted == original_plaintext:
                    print(f"   Message {i+1} decrypted successfully: '{decrypted}'")
                else:
                    print(f"    Message {i+1} decryption mismatch")
                    
            except Exception as e:
                print(f"    Message {i+1} decryption failed: {e}")
        
        print("\n6. Demonstrating persistent state management...")
        
        # Save Alice's session state
        alice_state_data = {
            'client_id': 'Alice',
            'ratchet_state': alice_session.get_state(),
            'last_updated': int(time.time())
        }
        
        success = state_manager.save_state('Alice', alice_state_data, 'alice_demo_password')
        if success:
            print("    Alice's session state saved successfully")
            
            # Create backup
            backup_path = state_manager.create_backup('Alice', 'alice_demo_password')
            if backup_path:
                print(f"    Session backup created: {backup_path}")
            
            # Test state loading
            loaded_state = state_manager.load_state('Alice', 'alice_demo_password')
            if loaded_state == alice_state_data:
                print("    Session state loaded and verified successfully")
            else:
                print("    Session state verification failed")
            
            # Cleanup
            state_manager.delete_state('Alice')
            if backup_path and Path(backup_path).exists():
                Path(backup_path).unlink()
                print("   ✅ Demo state files cleaned up")
        
        print("\n7. Demonstrating error handling and recovery...")
        
        # Test error handling
        test_errors = 0
        recovered_errors = 0
        
        def failing_operation():
            raise ValueError("Simulated encryption failure")
        
        success, result, error_info = error_handler.safe_execute(failing_operation)
        if not success:
            test_errors += 1
            recovery_suggestion = error_handler.create_recovery_suggestion(ValueError("test"))
            if recovery_suggestion:
                recovered_errors += 1
                print(f"   ✅ Error handled with recovery suggestion: {recovery_suggestion}")
        
        # Test retry mechanism
        attempts = 0
        def unreliable_operation():
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise ConnectionError("Simulated network failure")
            return "success"
        
        success, result, error_info = error_handler.retry_operation(unreliable_operation, max_retries=3)
        if success:
            print(f"   ✅ Retry mechanism succeeded after {attempts} attempts")
        
        # Show error statistics
        stats = error_handler.get_error_statistics()
        print(f"   Error statistics: {stats['total_errors']} total errors handled")
        
        
        return True
        
    except Exception as e:
        print(f" Core features demonstration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_network_demo():
    """Run the network demo with enhanced clients"""
    print_section("NETWORK DEMONSTRATION")
    
    print("This would start the enhanced server and clients.")
    print("To run the full network demo:")
    print()
    print("1. Terminal 1: python enhanced_server.py")
    print("2. Terminal 2: python enhanced_alice.py")
    print("3. Terminal 3: python enhanced_bob.py") 
    print("4. Terminal 4: python enhanced_malory.py")
    print()
    print("Each component includes all production-like features:")
    print("- X3DH key exchange with fallback")
    print("- Persistent state management")
    print("- Enhanced error handling")
    print("- Message validation and replay protection")
    print("- Comprehensive logging and monitoring")

def show_file_structure():
    """Show the enhanced file structure"""
    print_section("ENHANCED FILE STRUCTURE")
    
    files_info = [
        ("Core Implementation", [
            "double_ratchet.py - Complete Double Ratchet with session wrapper",
            "enhanced_alice.py - Alice client with all features",
            "enhanced_bob.py - Bob client with comprehensive enhancements", 
            "enhanced_server.py - Message relay with X3DH support",
            "enhanced_malory.py - Advanced cryptanalysis tool"
        ]),
        (" Modules", [
            "state_manager.py - Encrypted persistent state management",
            "message_handler.py - Enhanced message format with validation",
            "error_handler.py - Comprehensive error handling system",
            "x3dh_integration.py - Basic X3DH key agreement"
        ]),
        ("Testing & Demo", [
            "test_enhanced_features.py - Comprehensive test suite",
            "demo_enhanced_system.py - This demonstration script",
            "README_enhanced.md - Complete documentation"
        ])
    ]
    
    for category, files in files_info:
        print(f"\n{category}:")
        for file in files:
            print(f"  • {file}")

def main():
    print_banner()
    
    print("This demonstration shows Double Ratchet features")

    print()
    
    # Show file structure
    show_file_structure()
    
    # Run core features demonstration
    print("\nStarting core features demonstration...")
    core_success = demonstrate_core_features()
    
    if core_success:
        print("\nFeatures demonstrated!")
    else:
        print("\n Some features failed during demonstration")
        return False
    
    # Show network demo info
    run_network_demo()
 
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nDemonstration interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nDemonstration error: {e}")
        sys.exit(1)