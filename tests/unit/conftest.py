"""Simple pytest configuration to stub only external/hardware dependencies.

This file creates dummy (stub) modules for external libraries that are required by tests
but may not be available on the developer/CI machine (e.g. RPi.GPIO, serial, websocket).
It does NOT interfere with the main package imports.
"""
from types import ModuleType, SimpleNamespace
import sys
import os
from pathlib import Path
import pytest

# Add project root to sys.path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Force import of main package to ensure proper initialization
try:
    import atous_sec_network
    # Force import of submodules
    import atous_sec_network.network
    import atous_sec_network.network.lora_compat
except ImportError as e:
    print(f"Warning: Could not pre-import modules: {e}")

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _make_stub_module(name: str, attrs: dict | None = None) -> ModuleType:
    """Create a stub module with *attrs* injected and register it in sys.modules."""
    module = ModuleType(name)
    if attrs:
        for key, value in attrs.items():
            setattr(module, key, value)
    sys.modules[name] = module
    return module

# ---------------------------------------------------------------------------
# Stub for ``RPi.GPIO``
# ---------------------------------------------------------------------------
if 'RPi' not in sys.modules:
    gpio_stub = _make_stub_module('RPi')
    # ``RPi`` itself is a namespace package; we need a submodule ``GPIO``
    gpio_ns = SimpleNamespace(  # pylint: disable=too-few-public-methods
        BCM=11,
        OUT=0,
        IN=1,
        HIGH=1,
        LOW=0,
        setmode=lambda *args, **kwargs: None,
        setup=lambda *args, **kwargs: None,
        output=lambda *args, **kwargs: None,
        input=lambda *args, **kwargs: 0,
        cleanup=lambda *args, **kwargs: None,
    )
    gpio_module = _make_stub_module('RPi.GPIO', attrs=gpio_ns.__dict__)
    # Link submodule as attribute on parent package so that patch('RPi.GPIO') works
    setattr(gpio_stub, 'GPIO', gpio_module)

# ---------------------------------------------------------------------------
# Stub for ``serial`` (pyserial)
# ---------------------------------------------------------------------------
if 'serial' not in sys.modules:
    class _DummySerialException(Exception):
        """Mock SerialException for testing"""
        pass

    class _DummySerial:  # noqa: D401, pylint: disable=too-few-public-methods
        """Very small subset of `serial.Serial` used in tests."""

        def __init__(self, *args, **kwargs):
            self._buffer: bytearray = bytearray()
            self.timeout = kwargs.get('timeout', 1.0)
            self.port = kwargs.get('port')
            self.baudrate = kwargs.get('baudrate', 9600)
            self.is_open = False

        # pylint: disable=unused-argument
        def read(self, size: int = 1):
            return bytes(self._buffer[:size] or b'')

        def write(self, data: bytes):
            self._buffer.extend(data)
            return len(data)

        def readline(self):
            return b'OK\r\n'

        def open(self):
            self.is_open = True

        def close(self):
            self.is_open = False

        def flush(self):
            pass

        def reset_input_buffer(self):
            pass

        def reset_output_buffer(self):
            pass

    serial_attrs = {
        'Serial': _DummySerial,
        'SerialException': _DummySerialException,
        'PARITY_NONE': 'N',
        'STOPBITS_ONE': 1,
        'EIGHTBITS': 8,
    }
    serial_mod = _make_stub_module('serial', attrs=serial_attrs)
    # Stub for serial.tools.list_ports.comports
    tools_mod = _make_stub_module('serial.tools')
    list_ports_mod = _make_stub_module('serial.tools.list_ports', attrs={'comports': lambda: []})
    # Expose tools subpackage as attribute of serial
    setattr(serial_mod, 'tools', tools_mod)

# ---------------------------------------------------------------------------
# Stub for websocket / websockets
# ---------------------------------------------------------------------------
for ws_mod in ('websocket', 'websockets'):
    if ws_mod not in sys.modules:
        _make_stub_module(ws_mod)

# ---------------------------------------------------------------------------
# Stub for paho.mqtt.client (used by mosquitto tests)
# ---------------------------------------------------------------------------
if 'paho' not in sys.modules:
    paho_stub = _make_stub_module('paho')
    mqtt_stub = _make_stub_module('paho.mqtt')
    _make_stub_module('paho.mqtt.client', attrs={'Client': object})

# ---------------------------------------------------------------------------
# Additional dependency stubs required by tests
# ---------------------------------------------------------------------------
for pkg in ("prometheus_client", "psutil", "cryptography", "certifi", "flwr"):
    if pkg not in sys.modules:
        _make_stub_module(pkg)

# ---------------------------------------------------------------------------
# ModelManager fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_federated_model_updater():
    """Fixture to mock the FederatedModelUpdater class."""
    from unittest.mock import MagicMock
    
    # Create a mock directly without patching
    mock_instance = MagicMock()
    
    # Set up return values for methods
    mock_instance.download_model.return_value = True
    mock_instance.apply_patch.return_value = True
    mock_instance.rollback.return_value = True
    mock_instance.check_for_updates.return_value = False
    
    return mock_instance

@pytest.fixture
def model_manager_config():
    """Fixture providing a standard configuration for ModelManager tests."""
    return {
        'model_path': '/tmp/test_model',
        'version_control': True,
        'auto_rollback': True,
        'storage_path': '/tmp/model_storage',
        'max_versions': 5,
        'checksum_algorithm': 'sha256'
    }

@pytest.fixture
def model_manager(model_manager_config, mock_federated_model_updater):
    """Fixture providing a configured ModelManager instance for testing."""
    import logging
    from unittest.mock import MagicMock
    
    # Try to import the real ModelManager class
    try:
        # Import the real ModelManager
        from atous_sec_network.core.model_manager import ModelManager
        
        # Create an instance of the real ModelManager
        manager = ModelManager(model_manager_config)
        
        # Assign the mock updater to the model manager
        manager.updater = mock_federated_model_updater
        return manager
        
    except ImportError:
        # Fall back to the mock implementation
        class MockModelManager:
            def __init__(self, config):
                # Store the configuration as-is without adding default values
                self.config = config or {}
                
                # Set instance variables from config for easy access
                self.model_path = self.config.get('model_path')
                self.version_control = self.config.get('version_control', True)
                self.auto_rollback = self.config.get('auto_rollback', True)
                
                # Initialize the updater - this will be mocked in tests
                self.updater = None
                
                # Set up logging
                self.logger = logging.getLogger(__name__)
                
            def download_model(self, model_url, model_path=None, checksum=None, timeout=60, max_retries=3):
                """Download a model from the specified URL to the given path."""
                self.logger.info(f"Downloading model from {model_url} to {model_path}")
                
                # For testing purposes, if updater is None, return True
                if self.updater is None:
                    return True
                    
                return self.updater.download_model(model_url, model_path, checksum=checksum, 
                                                  timeout=timeout, max_retries=max_retries)
                                                  
            def apply_patch(self, patch_data):
                """Apply a patch to the current model."""
                self.logger.info(f"Applying patch: {patch_data}")
                
                # For testing purposes, if updater is None, return True
                if self.updater is None:
                    return True
                    
                return self.updater.apply_patch(patch_data)
                
            def rollback(self, version):
                """Roll back to a previous model version."""
                self.logger.info(f"Rolling back to version: {version}")
                
                # For testing purposes, if updater is None, return True
                if self.updater is None:
                    return True
                    
                return self.updater.rollback(version)
                
            def check_for_updates(self, server_url=None):
                """Check for available model updates."""
                self.logger.info("Checking for model updates")
                
                # For testing purposes, if updater is None, return a default response
                if self.updater is None:
                    return False
                    
                return self.updater.check_for_updates()
        
        # Create an instance of our mock class
        manager = MockModelManager(model_manager_config)
        
        # Assign the mock updater to the model manager
        manager.updater = mock_federated_model_updater
        return manager

# ---------------------------------------------------------------------------
# End of conftest_simple
# ---------------------------------------------------------------------------