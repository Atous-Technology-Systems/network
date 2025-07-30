"""Conftest for LoRa tests"""
import sys
import os
from pathlib import Path
from unittest.mock import MagicMock
import pytest

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Create mock GPIO
class MockGPIO:
    BCM = 'BCM'
    BOARD = 'BOARD'
    OUT = 'OUT'
    IN = 'IN'
    HIGH = 1
    LOW = 0
    
    @staticmethod
    def setmode(mode):
        pass
        
    @staticmethod
    def setup(pin, mode):
        pass
        
    @staticmethod
    def output(pin, value):
        pass
        
    @staticmethod
    def input(pin):
        return MockGPIO.LOW
        
    @staticmethod
    def cleanup():
        pass

# Mock the GPIO module
sys.modules['RPi'] = MagicMock()
sys.modules['RPi.GPIO'] = MockGPIO()

# Create a fixture for the LoRaOptimizer
@pytest.fixture
def lora_optimizer():
    """Fixture for LoRaOptimizer"""
    # Import here to avoid pytest rewriting issues
    from atous_sec_network.network.lora_compat import LoRaOptimizer
    return LoRaOptimizer()

# Create a fixture for the mocked hardware interface
@pytest.fixture
def mock_hardware_interface(monkeypatch):
    """Fixture for mocked hardware interface"""
    mock_interface = MagicMock()
    # Ensure send_command returns a tuple of (success, response)
    mock_interface.send_command.return_value = (True, "OK")
    monkeypatch.setattr('atous_sec_network.network.lora_compat.LoraHardwareInterface', 
                      lambda **kwargs: mock_interface)
    return mock_interface