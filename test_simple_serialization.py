#!/usr/bin/env python3
"""
Simple test to verify DoubleRatchetSession state serialization
"""

import sys
import os
import json

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.core.double_ratchet import DoubleRatchetSession
    
    print("Testing DoubleRatchetSession state serialization...")
    
    # Create a session
    session = DoubleRatchetSession()
    
    # Try to get state (should be None initially)
    state = session.get_state()
    print(f"Initial state: {state}")
    
    if state is None:
        print("✅ get_state() returns None for uninitialized session")
    else:
        # Try JSON serialization
        try:
            json_str = json.dumps(state)
            print("✅ JSON serialization successful")
            print(f"State keys: {list(state.keys()) if isinstance(state, dict) else 'Not a dict'}")
        except Exception as e:
            print(f"❌ JSON serialization failed: {e}")
            
    print("✅ Basic test completed")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()