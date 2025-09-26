#!/usr/bin/env python3
"""
Test script to verify state serialization fix
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.core.double_ratchet import DoubleRatchetSession  # type: ignore
    from src.security.x3dh import X3DH  # type: ignore
    import json
    
    print("Testing state serialization fix...")
    
    # Create a Double Ratchet session
    session = DoubleRatchetSession("test_session")
    
    # Initialize with X3DH
    x3dh = X3DH()
    alice_bundle = x3dh.generate_key_bundle("Alice")
    
    # Perform key exchange simulation
    try:
        session.initialize_with_x3dh(alice_bundle, None, True)  # As initiator
        print("✅ Session initialized successfully")
        
        # Test state serialization
        state = session.get_state()
        if state is not None:
            # Try to serialize to JSON (this was failing before)
            json_state = json.dumps(state)
            print("✅ State serialization successful")
            print(f"📊 Serialized state size: {len(json_state)} bytes")
            
            # Test deserialization
            parsed_state = json.loads(json_state)
            print("✅ State deserialization successful")
            
            # Test state restoration
            new_session = DoubleRatchetSession("test_session_2")
            new_session.restore_state(parsed_state)
            print("✅ State restoration successful")
            
            print("\n🎉 All serialization tests passed!")
            
        else:
            print("❌ State is None")
            
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all dependencies are installed and paths are correct")
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()