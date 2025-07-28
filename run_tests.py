"""
Simple test runner for Atous Secure Network tests.
This script sets up a clean environment and runs the specified tests.
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Mock external dependencies
sys.modules['RPi'] = MagicMock()
sys.modules['RPi.GPIO'] = MagicMock()
sys.modules['serial'] = MagicMock()
sys.modules['serial.tools'] = MagicMock()
sys.modules['serial.tools.list_ports'] = MagicMock()

# Mock the ModelManager dependencies
class MockFederatedModelUpdater:
    def __init__(self, *args, **kwargs):
        pass
    def download_model(self, *args, **kwargs):
        return True
    def apply_patch(self, *args, **kwargs):
        return True
    def rollback(self, *args, **kwargs):
        return True
    def check_for_updates(self, *args, **kwargs):
        return {}

# Patch the ModelManager imports
with patch.dict('sys.modules', {
    'atous_sec_network.core.model_manager': MagicMock(FederatedModelUpdater=MockFederatedModelUpdater),
}):
    # Now import the test module
    from tests.unit.test_model_manager_fixed import TestModelManager

if __name__ == '__main__':
    # Run the tests
    unittest.main(module='tests.unit.test_model_manager_fixed', verbosity=2)
