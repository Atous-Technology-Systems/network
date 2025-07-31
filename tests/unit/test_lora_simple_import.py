#!/usr/bin/env python3
"""
Simple test for LoRaOptimizer import and basic functionality.
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Debug information
print(f"DEBUG: __file__ = {__file__}")
print(f"DEBUG: project_root = {project_root}")
print(f"DEBUG: project_root.exists() = {project_root.exists()}")
print(f"DEBUG: sys.path[0] = {sys.path[0]}")

# Test module-level imports
try:
    import atous_sec_network
    print("DEBUG: Successfully imported atous_sec_network")
except Exception as e:
    print(f"DEBUG: Failed to import atous_sec_network: {e}")

try:
    import atous_sec_network.network
    print("DEBUG: Successfully imported atous_sec_network.network")
except Exception as e:
    print(f"DEBUG: Failed to import atous_sec_network.network: {e}")

try:
    from atous_sec_network.network.lora_compat import LoRaOptimizer
    print("DEBUG: Successfully imported LoRaOptimizer")
except Exception as e:
    print(f"DEBUG: Failed to import LoRaOptimizer: {e}")

def test_import_lora_optimizer():
    """Test that LoRaOptimizer can be imported."""
    # Ensure the project root is in sys.path
    project_root = Path(__file__).parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    # Import LoRaOptimizer
    from atous_sec_network.network.lora_compat import LoRaOptimizer
    assert LoRaOptimizer is not None

def test_create_lora_optimizer():
    """Test that LoRaOptimizer can be instantiated."""
    # Ensure the project root is in sys.path
    project_root = Path(__file__).parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    # Import and instantiate LoRaOptimizer
    from atous_sec_network.network.lora_compat import LoRaOptimizer
    lora = LoRaOptimizer()
    assert lora is not None
    assert hasattr(lora, 'initialize')
    assert hasattr(lora, 'send_data')
    assert hasattr(lora, 'receive_data')

def test_lora_optimizer_methods(monkeypatch):
    """Test that LoRaOptimizer methods work correctly."""
    # Ensure the project root is in sys.path
    project_root = Path(__file__).parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    # Mock the hardware interface to avoid hardware dependencies
    from atous_sec_network.network import lora_compat
    
    class MockHardwareInterface:
        def __init__(self, port=None, baudrate=9600):
            self.port = port
            self.baudrate = baudrate
            self.initialized = False
            
        def send_command(self, command):
            """Mock send_command method that returns success and response"""
            if command == "AT+RECV":
                return True, "test_data"
            return True, "OK"
            
        def send_data(self, data):
            return True
            
        def receive_data(self):
            return b"test_data"
    
    class MockLoraAdaptiveEngine:
        def __init__(self, config):
            self.config = config
    
    # Patch the hardware interface and engine in the lora_compat module
    monkeypatch.setattr(lora_compat, 'LoraHardwareInterface', MockHardwareInterface)
    monkeypatch.setattr(lora_compat, 'LoraAdaptiveEngine', MockLoraAdaptiveEngine)
    
    # Import and test LoRaOptimizer
    from atous_sec_network.network.lora_compat import LoRaOptimizer
    lora = LoRaOptimizer()
    
    # Test initialization with required port parameter
    result = lora.initialize(port="COM1", baud=9600)
    assert result is True
    
    # Test send_data
    result = lora.send_data(b"test")
    assert result is True
    
    # Test receive_data
    data = lora.receive_data()
    assert data == "test_data"