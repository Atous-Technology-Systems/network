#!/usr/bin/env python3
"""
Test direct import of LoRaOptimizer with file-based approach.

This file tests that the LoRaOptimizer class can be imported and used correctly
by directly executing the module files.
"""
import sys
import os
import importlib.util
from pathlib import Path
import pytest

# Ensure project root is in path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Create mock GPIO before importing
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

# Mock the GPIO module if not already mocked
if 'RPi' not in sys.modules:
    sys.modules['RPi'] = type('RPi', (), {})()
if 'RPi.GPIO' not in sys.modules:
    sys.modules['RPi.GPIO'] = MockGPIO

# Mock serial module with SerialException
class MockSerialException(Exception):
    """Mock SerialException for testing"""
    pass

class MockSerial:
    """Mock serial.Serial class for testing"""
    
    def __init__(self, port=None, baudrate=9600, timeout=1, **kwargs):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.is_open = False
        
    def open(self):
        self.is_open = True
        
    def close(self):
        self.is_open = False
        
    def write(self, data):
        return len(data)
        
    def read(self, size=1):
        return b''
        
    def readline(self):
        return b'OK\r\n'
        
    def flush(self):
        pass
        
    def reset_input_buffer(self):
        pass
        
    def reset_output_buffer(self):
        pass

# Create mock serial module
serial_mock = type('serial', (), {
    'Serial': MockSerial,
    'SerialException': MockSerialException,
    'PARITY_NONE': 'N',
    'STOPBITS_ONE': 1,
    'EIGHTBITS': 8,
})

# Mock serial.tools.list_ports
list_ports_mock = type('list_ports', (), {
    'comports': lambda: []
})
serial_tools_mock = type('tools', (), {
    'list_ports': list_ports_mock
})
serial_mock.tools = serial_tools_mock

# Install serial mock (force override)
sys.modules['serial'] = serial_mock
sys.modules['serial.tools'] = serial_tools_mock
sys.modules['serial.tools.list_ports'] = list_ports_mock


class TestLoRaOptimizerImport:
    """Test class for LoRaOptimizer import and basic functionality."""
    
    def test_files_exist(self):
        """Test that required files exist."""
        base_path = project_root / "atous_sec_network"
        network_path = base_path / "network"
        lora_compat_path = network_path / "lora_compat.py"
        lora_optimizer_path = network_path / "lora_optimizer.py"
        
        assert base_path.exists(), f"Base package directory should exist: {base_path}"
        assert network_path.exists(), f"Network package directory should exist: {network_path}"
        assert lora_compat_path.exists(), f"LoRa compat file should exist: {lora_compat_path}"
        assert lora_optimizer_path.exists(), f"LoRa optimizer file should exist: {lora_optimizer_path}"
    
    def test_package_init_files(self):
        """Test that __init__.py files exist."""
        base_init = project_root / "atous_sec_network" / "__init__.py"
        network_init = project_root / "atous_sec_network" / "network" / "__init__.py"
        
        assert base_init.exists(), f"Base __init__.py should exist: {base_init}"
        assert network_init.exists(), f"Network __init__.py should exist: {network_init}"
    
    def test_load_lora_compat_module(self):
        """Test loading lora_compat module directly."""
        lora_compat_path = project_root / "atous_sec_network" / "network" / "lora_compat.py"
        
        # Load the module directly using importlib.util
        spec = importlib.util.spec_from_file_location("lora_compat", lora_compat_path)
        assert spec is not None, "Module spec should be created"
        
        # We'll test that the spec can be created, but not execute it yet
        # to avoid import issues
        assert spec.loader is not None, "Module loader should be available"
    
    def test_load_lora_optimizer_module(self):
        """Test loading lora_optimizer module directly."""
        lora_optimizer_path = project_root / "atous_sec_network" / "network" / "lora_optimizer.py"
        
        # Load the module directly using importlib.util
        spec = importlib.util.spec_from_file_location("lora_optimizer", lora_optimizer_path)
        assert spec is not None, "Module spec should be created"
        assert spec.loader is not None, "Module loader should be available"
    
    def test_execute_lora_optimizer_module(self):
        """Test executing lora_optimizer module."""
        lora_optimizer_path = project_root / "atous_sec_network" / "network" / "lora_optimizer.py"
        
        # Load and execute the module
        spec = importlib.util.spec_from_file_location("lora_optimizer", lora_optimizer_path)
        lora_optimizer_module = importlib.util.module_from_spec(spec)
        
        # Add to sys.modules to handle internal imports
        sys.modules['lora_optimizer'] = lora_optimizer_module
        
        try:
            spec.loader.exec_module(lora_optimizer_module)
            
            # Check that expected classes exist
            assert hasattr(lora_optimizer_module, 'LoraHardwareInterface'), "LoraHardwareInterface should exist"
            assert hasattr(lora_optimizer_module, 'LoraAdaptiveEngine'), "LoraAdaptiveEngine should exist"
            
        except Exception as e:
            pytest.fail(f"Failed to execute lora_optimizer module: {e}")
        finally:
            # Clean up
            if 'lora_optimizer' in sys.modules:
                del sys.modules['lora_optimizer']
    
    def test_execute_lora_compat_module(self):
        """Test executing lora_compat module."""
        # First load lora_optimizer as a dependency
        lora_optimizer_path = project_root / "atous_sec_network" / "network" / "lora_optimizer.py"
        lora_compat_path = project_root / "atous_sec_network" / "network" / "lora_compat.py"
        
        # Load lora_optimizer first with proper module name
        optimizer_spec = importlib.util.spec_from_file_location("atous_sec_network.network.lora_optimizer", lora_optimizer_path)
        optimizer_module = importlib.util.module_from_spec(optimizer_spec)
        sys.modules['atous_sec_network.network.lora_optimizer'] = optimizer_module
        
        try:
            optimizer_spec.loader.exec_module(optimizer_module)
            
            # Now load lora_compat with proper module name for relative imports
            compat_spec = importlib.util.spec_from_file_location("atous_sec_network.network.lora_compat", lora_compat_path)
            compat_module = importlib.util.module_from_spec(compat_spec)
            
            # Set up the module hierarchy for relative imports
            compat_module.__package__ = "atous_sec_network.network"
            
            sys.modules['atous_sec_network.network.lora_compat'] = compat_module
            compat_spec.loader.exec_module(compat_module)
            
            # Check that LoRaOptimizer exists
            assert hasattr(compat_module, 'LoRaOptimizer'), "LoRaOptimizer should exist"
            
            # Test instantiation
            LoRaOptimizer = getattr(compat_module, 'LoRaOptimizer')
            lora = LoRaOptimizer()
            assert lora is not None, "LoRaOptimizer should be instantiable"
            
            # Test basic methods
            assert hasattr(lora, 'initialize'), "LoRaOptimizer should have initialize method"
            assert hasattr(lora, 'send_data'), "LoRaOptimizer should have send_data method"
            assert hasattr(lora, 'receive_data'), "LoRaOptimizer should have receive_data method"
            
        except Exception as e:
            pytest.fail(f"Failed to execute lora_compat module: {e}")
        finally:
            # Clean up
            for module in ['atous_sec_network.network.lora_optimizer', 'atous_sec_network.network.lora_compat']:
                if module in sys.modules:
                    del sys.modules[module]
    
    def test_lora_optimizer_functionality(self):
        """Test basic LoRaOptimizer functionality."""
        # Load modules as in previous test
        lora_optimizer_path = project_root / "atous_sec_network" / "network" / "lora_optimizer.py"
        lora_compat_path = project_root / "atous_sec_network" / "network" / "lora_compat.py"
        
        # Load lora_optimizer first with proper module name
        optimizer_spec = importlib.util.spec_from_file_location("atous_sec_network.network.lora_optimizer", lora_optimizer_path)
        optimizer_module = importlib.util.module_from_spec(optimizer_spec)
        sys.modules['atous_sec_network.network.lora_optimizer'] = optimizer_module
        
        try:
            optimizer_spec.loader.exec_module(optimizer_module)
            
            # Now load lora_compat with proper module name for relative imports
            compat_spec = importlib.util.spec_from_file_location("atous_sec_network.network.lora_compat", lora_compat_path)
            compat_module = importlib.util.module_from_spec(compat_spec)
            
            # Set up the module hierarchy for relative imports
            compat_module.__package__ = "atous_sec_network.network"
            
            sys.modules['atous_sec_network.network.lora_compat'] = compat_module
            compat_spec.loader.exec_module(compat_module)
            
            # Test functionality
            LoRaOptimizer = getattr(compat_module, 'LoRaOptimizer')
            lora = LoRaOptimizer()
            
            # Test methods don't raise exceptions with mocked hardware
            try:
                # These should work with mocked GPIO
                result = lora.send_data(b"test_data")
                assert isinstance(result, bool), "send_data should return boolean"
                
                recv_data = lora.receive_data()
                assert recv_data is None or isinstance(recv_data, bytes), "receive_data should return bytes or None"
                
            except Exception as e:
                pytest.fail(f"LoRaOptimizer methods should not raise exceptions with mocked hardware: {e}")
                
        except Exception as e:
            pytest.fail(f"Failed to test LoRaOptimizer functionality: {e}")
        finally:
            # Clean up
            for module in ['atous_sec_network.network.lora_optimizer', 'atous_sec_network.network.lora_compat']:
                if module in sys.modules:
                    del sys.modules[module]