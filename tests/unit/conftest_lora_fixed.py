"""Pytest configuration file for LoRa tests."""
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

@pytest.fixture
def mock_hardware_interface():
    """Create a mock hardware interface for testing."""
    mock_hw = MagicMock()
    mock_hw.send_command.return_value = (True, "OK")
    mock_hw.send.return_value = True
    mock_hw.receive.return_value = b'received data'
    return mock_hw

@pytest.fixture
def lora_optimizer(monkeypatch, mock_hardware_interface):
    """Create a LoRaOptimizer instance for testing."""
    # Import here to ensure sys.path is set up correctly
    from atous_sec_network.network.lora_compat import LoRaOptimizer
    from atous_sec_network.network.lora_compat import LoraHardwareInterface
    
    # Patch the LoraHardwareInterface
    monkeypatch.setattr(
        'atous_sec_network.network.lora_compat.LoraHardwareInterface',
        lambda: mock_hardware_interface
    )
    
    # Create and return the LoRaOptimizer
    return LoRaOptimizer()