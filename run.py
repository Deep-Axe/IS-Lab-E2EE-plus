#!/usr/bin/env python3
"""
Enhanced Double Ratchet System Runner
Simple script to run the enhanced system with proper Python path setup.
"""

import os
import sys
import subprocess
import time
import threading
from pathlib import Path

def setup_python_path():
    """Add the src directory to Python path for imports"""
    project_root = Path(__file__).parent
    src_path = project_root / 'src'
    
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
    
    # Also set PYTHONPATH environment variable
    current_pythonpath = os.environ.get('PYTHONPATH', '')
    if str(src_path) not in current_pythonpath:
        if current_pythonpath:
            os.environ['PYTHONPATH'] = f"{src_path};{current_pythonpath}"
        else:
            os.environ['PYTHONPATH'] = str(src_path)

def run_component(component_name, script_path):
    """Run a component with proper environment setup"""
    print(f"Starting {component_name}...")
    try:
        env = os.environ.copy()
        result = subprocess.run([
            sys.executable, script_path
        ], env=env, cwd=os.path.dirname(script_path))
        return result.returncode
    except Exception as e:
        print(f"Error running {component_name}: {e}")
        return 1

def main():
    """Main runner function"""
    setup_python_path()
    
    project_root = Path(__file__).parent
    
    components = {
        'server': project_root / 'src' / 'network' / 'enhanced_server.py',
        'alice': project_root / 'src' / 'network' / 'enhanced_alice.py', 
        'bob': project_root / 'src' / 'network' / 'enhanced_bob.py',
        'multi-client': project_root / 'src' / 'network' / 'enhanced_multi_client.py',
        'malory': project_root / 'tools' / 'interactive_malory.py',
        'demo': project_root / 'examples' / 'demo_enhanced_system.py',
        'simple-demo': project_root / 'examples' / 'demo_simple_working.py',
        'test': project_root / 'tests' / 'test_enhanced_features.py'
    }
    
    if len(sys.argv) < 2:
        print("Enhanced Double Ratchet System Runner")
        print("====================================")
        print()
        print("Usage: python run.py <component>")
        print()
        print("Available components:")
        for name, path in components.items():
            print(f"  {name:12} - {path.name}")
        print()
        print("Examples:")
        print("  python run.py demo       # Run complete system demo")
        print("  python run.py server     # Start message relay server")
        print("  python run.py bob        # Start Bob client")
        print("  python run.py alice      # Start Alice client")
        print("  python run.py test       # Run test suite")
        return 1
    
    component = sys.argv[1].lower()
    
    if component not in components:
        print(f"Unknown component: {component}")
        print(f"Available components: {', '.join(components.keys())}")
        return 1
    
    script_path = components[component]
    
    if not script_path.exists():
        print(f"Script not found: {script_path}")
        return 1
    
    return run_component(component, str(script_path))

if __name__ == '__main__':
    sys.exit(main())