import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Try to import ModelManager
from atous_sec_network.core.model_manager import ModelManager

# Create an instance
manager = ModelManager({})

print(f"ModelManager imported successfully: {manager}")