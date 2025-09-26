#!/usr/bin/env python3
"""
Import Test Script for Enhanced Double Ratchet Implementation
Tests that all modules can be imported correctly with the new structure.
"""

import os
import sys
from pathlib import Path

def setup_path():
    """Setup Python path for imports"""
    project_root = Path(__file__).parent
    src_path = project_root / 'src'
    sys.path.insert(0, str(src_path))

def test_imports():
    """Test all module imports"""
    setup_path()
    
    print("Enhanced Double Ratchet - Import Test")
    print("=" * 40)
    
    tests = [
        ("Core Double Ratchet", "core.double_ratchet", "DoubleRatchetSession"),
        ("X3DH Integration", "security.x3dh_integration", "X3DHSession"),
        ("State Manager", "utils.state_manager", "StateManager"),
        ("Message Handler", "utils.message_handler", "MessageHandler"),
        ("Error Handler", "utils.error_handler", "ErrorHandler"),
        ("Alice Client", "network.enhanced_alice", "EnhancedAliceClient"),
        ("Bob Client", "network.enhanced_bob", "EnhancedBobClient"),
        ("Enhanced Server", "network.enhanced_server", "EnhancedServer"),
    ]
    
    success_count = 0
    total_count = len(tests)
    
    for test_name, module_name, class_name in tests:
        try:
            module = __import__(module_name, fromlist=[class_name])
            getattr(module, class_name)  # Verify class exists
            print(f"✅ {test_name:20} - Import successful")
            success_count += 1
        except ImportError as e:
            print(f"❌ {test_name:20} - Import failed: {e}")
        except AttributeError as e:
            print(f"❌ {test_name:20} - Class not found: {e}")
        except Exception as e:
            print(f"❌ {test_name:20} - Unexpected error: {e}")
    
    print()
    print(f"Import Test Results: {success_count}/{total_count} successful")
    
    if success_count == total_count:
        print("🎉 All imports successful! The modular structure is working correctly.")
        return True
    else:
        print("⚠️  Some imports failed. Check the module structure and imports.")
        return False

def test_package_imports():
    """Test package-level imports"""
    setup_path()
    
    print("\nPackage Import Test")
    print("=" * 20)
    
    package_tests = [
        ("Main Package", "src", None),
        ("Core Package", "src.core", None),
        ("Security Package", "src.security", None),
        ("Utils Package", "src.utils", None),
        ("Network Package", "src.network", None),
    ]
    
    for test_name, package_name, _ in package_tests:
        try:
            __import__(package_name)
            print(f"✅ {test_name:20} - Package import successful")
        except ImportError as e:
            print(f"❌ {test_name:20} - Package import failed: {e}")

if __name__ == '__main__':
    success = test_imports()
    test_package_imports()
    
    if success:
        print("\n🚀 Ready to run the enhanced system!")
        print("Try: python run.py demo")
    else:
        print("\n🔧 Some issues need to be fixed before running.")
    
    sys.exit(0 if success else 1)