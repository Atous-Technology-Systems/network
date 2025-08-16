#!/usr/bin/env python3
"""
ATous Secure Network - Debug Import Script (Convenience Wrapper)
This script runs the debug_import.py from the scripts directory
"""

import os
import sys
import subprocess

def main():
    """Run the debug import script from the scripts directory"""
    # Get the directory where this script is located
    current_dir = os.path.dirname(os.path.abspath(__file__))
    scripts_dir = os.path.join(current_dir, 'scripts')
    debug_script = os.path.join(scripts_dir, 'debug_import.py')
    
    # Check if the debug script exists
    if not os.path.exists(debug_script):
        print(f"❌ Error: debug_import.py not found in {scripts_dir}")
        print("Please ensure you're running this from the project root directory")
        sys.exit(1)
    
    # Set PYTHONPATH to include the current directory
    env = os.environ.copy()
    if 'PYTHONPATH' in env:
        env['PYTHONPATH'] = current_dir + os.pathsep + env['PYTHONPATH']
    else:
        env['PYTHONPATH'] = current_dir
    
    # Run the debug script with the correct PYTHONPATH
    try:
        result = subprocess.run([sys.executable, debug_script], 
                              capture_output=False, text=True, env=env)
        return result.returncode
    except Exception as e:
        print(f"❌ Error running debug_import.py: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
