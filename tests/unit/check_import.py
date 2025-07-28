import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Try to import ModelManager
try:
    from atous_sec_network.core.model_manager import ModelManager
    print("Successfully imported ModelManager")
    print(f"ModelManager class: {ModelManager}")
except ImportError as e:
    print(f"Failed to import ModelManager: {e}")
    
    # Print the sys.path to debug
    print("\nPython path:")
    for path in sys.path:
        print(f"  {path}")
    
    # Check if the file exists
    model_manager_path = os.path.join(os.path.dirname(__file__), '../../atous_sec_network/core/model_manager.py')
    print(f"\nDoes model_manager.py exist? {os.path.exists(model_manager_path)}")
    print(f"Path: {os.path.abspath(model_manager_path)}")