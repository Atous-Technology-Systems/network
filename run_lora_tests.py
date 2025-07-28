"""
Isolated test runner for LoRa compatibility tests.
This script sets up a clean environment and runs the tests without loading conftest.py
"""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Set up the Python path
sys.path.insert(0, os.path.abspath('.'))

# Mock external dependencies before any imports
sys.modules['RPi'] = MagicMock()
sys.modules['RPi'].GPIO = MagicMock()
sys.modules['serial'] = MagicMock()
sys.modules['serial.tools'] = MagicMock()
sys.modules['serial.tools.list_ports'] = MagicMock()

# Define mock classes
class MockLoraAdaptiveEngine:
    def __init__(self, *args, **kwargs):
        self.initialized = False
    
    def initialize(self):
        self.initialized = True
        return True
    
    def send(self, message):
        if not self.initialized:
            raise RuntimeError("Not initialized")
        return True
    
    def receive(self):
        if not self.initialized:
            raise RuntimeError("Not initialized")
        return b'test message'

class MockLoraHardwareInterface:
    def __init__(self, *args, **kwargs):
        pass

# Patch the imports
with patch.dict('sys.modules', {
    'atous_sec_network.network.lora_adaptive_engine': MagicMock(
        LoraAdaptiveEngine=MockLoraAdaptiveEngine
    ),
    'atous_sec_network.network.lora_hardware_interface': MagicMock(
        LoraHardwareInterface=MockLoraHardwareInterface
    ),
    'atous_sec_network.network.lora_compat': MagicMock()
}):
    # Now import the test module
    from tests.unit.test_lora_compat_isolated import TestLoRaOptimizerIsolated

if __name__ == '__main__':
    # Run the tests with verbosity
    unittest.main(module='tests.unit.test_lora_compat_isolated', verbosity=2)
