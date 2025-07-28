"""
Pytest configuration with fixed stubs for testing.
This version removes problematic code and keeps only essential stubs.
"""
import sys
import os
from types import ModuleType

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def _make_stub_module(name: str, attrs: dict = None) -> ModuleType:
    """Create a stub module with the given attributes."""
    module = ModuleType(name)
    if attrs:
        for key, value in attrs.items():
            setattr(module, key, value)
    return module

# Stub for ModelManager and FederatedModelUpdater
if 'atous_sec_network.core.model_manager' not in sys.modules:
    mm_mod = _make_stub_module('atous_sec_network.core.model_manager')
    
    class _ModelManagerStub:
        def __init__(self, *args, **kwargs):
            self.config = kwargs.get('config', {})
            self.model_path = self.config.get('model_path', '')
            self.version_control = self.config.get('version_control', True)
            self.auto_rollback = self.config.get('auto_rollback', True)
            
        def download_model(self, *args, **kwargs):
            return True
            
        def apply_patch(self, *args, **kwargs):
            return True
            
        def rollback(self, *args, **kwargs):
            return True
            
        def check_for_updates(self, *args, **kwargs):
            return {}
    
    class _FederatedModelUpdaterStub:
        def __init__(self, *args, **kwargs):
            pass
            
        def update(self, *args, **kwargs):
            return True
            
        def apply_patch(self, *args, **kwargs):
            return True
            
        def rollback(self, *args, **kwargs):
            return True
            
        def check_for_updates(self, *args, **kwargs):
            return {}
    
    # Add the stubs to the module
    mm_mod.ModelManager = _ModelManagerStub
    mm_mod.FederatedModelUpdater = _FederatedModelUpdaterStub
    sys.modules['atous_sec_network.core.model_manager'] = mm_mod

# Stub for RPi.GPIO
if 'RPi' not in sys.modules:
    rpi_gpio = _make_stub_module('RPi.GPIO')
    rpi_gpio.IN = 1
    rpi_gpio.OUT = 0
    rpi_gpio.HIGH = 1
    rpi_gpio.LOW = 0
    rpi_gpio.PUD_UP = 0
    rpi_gpio.PUD_DOWN = 1
    rpi_gpio.BOARD = 10
    rpi_gpio.BCM = 11
    rpi_gpio.setmode = lambda x: None
    rpi_gpio.setwarnings = lambda x: None
    rpi_gpio.setup = lambda *args, **kwargs: None
    rpi_gpio.output = lambda *args, **kwargs: None
    rpi_gpio.input = lambda *args: 0
    rpi_gpio.cleanup = lambda *args: None
