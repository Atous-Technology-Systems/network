"""Basic test for LoRa functionality"""
import unittest
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

class TestLoRaBasic(unittest.TestCase):
    """Basic test for LoRa functionality"""
    
    def test_import_network_module(self):
        """Test that we can import the network module."""
        try:
            import atous_sec_network.network
            self.assertTrue(True, "Network module imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import network module: {e}")
    
    def test_import_lora_optimizer(self):
        """Test that we can import the lora_optimizer module."""
        try:
            from atous_sec_network.network import lora_optimizer
            self.assertTrue(True, "lora_optimizer module imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import lora_optimizer module: {e}")
    
    def test_import_lora_compat(self):
        """Test that we can import the lora_compat module."""
        try:
            from atous_sec_network.network import lora_compat
            self.assertTrue(True, "lora_compat module imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import lora_compat module: {e}")
    
    def test_import_lora_optimizer_classes(self):
        """Test that we can import classes from lora_optimizer."""
        try:
            from atous_sec_network.network.lora_optimizer import LoraAdaptiveEngine, LoraHardwareInterface
            self.assertTrue(True, "LoraAdaptiveEngine and LoraHardwareInterface imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import classes from lora_optimizer: {e}")
    
    def test_import_lora_compat_classes(self):
        """Test that we can import classes from lora_compat."""
        try:
            from atous_sec_network.network.lora_compat import LoRaOptimizer
            self.assertTrue(True, "LoRaOptimizer imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import LoRaOptimizer from lora_compat: {e}")

if __name__ == '__main__':
    unittest.main() 