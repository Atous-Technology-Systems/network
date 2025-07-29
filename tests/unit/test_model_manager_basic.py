"""
Basic tests for the ModelManager class.

This module contains tests for the core functionality of the ModelManager class,
focusing on the implemented methods and their expected behavior.
"""
import os
import sys
import unittest
import tempfile
import shutil
import json
from unittest.mock import MagicMock, patch, mock_open

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Mock external dependencies
sys.modules['RPi'] = MagicMock()
sys.modules['RPi.GPIO'] = MagicMock()
sys.modules['serial'] = MagicMock()
sys.modules['serial.tools'] = MagicMock()
sys.modules['serial.tools.list_ports'] = MagicMock()

class TestModelManagerBasic(unittest.TestCase):
    """Basic tests for the ModelManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.model_path = os.path.join(self.test_dir, 'test_model.bin')
        self.storage_path = os.path.join(self.test_dir, 'model_storage')
        
        # Create necessary directories
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Create a test model file
        self.test_data = b'test model data for basic tests'
        with open(self.model_path, 'wb') as f:
            f.write(self.test_data)
        
        # Mock FederatedModelUpdater
        self.mock_updater = MagicMock()
        self.mock_updater_class = MagicMock(return_value=self.mock_updater)
        
        # Patch the FederatedModelUpdater import
        self.patcher = patch('atous_sec_network.core.model_manager_impl.FederatedModelUpdater', 
                           self.mock_updater_class)
        self.patcher.start()
        
        # Import ModelManagerImpl after patching
        from atous_sec_network.core.model_manager_impl import ModelManagerImpl
        self.ModelManager = ModelManagerImpl
    
    def tearDown(self):
        """Clean up after tests."""
        self.patcher.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test that ModelManager initializes with default configuration."""
        manager = self.ModelManager()
        self.assertIsNotNone(manager)
        self.assertEqual(manager.config['storage_path'], 'models')
        self.assertTrue(manager.config['auto_update'])
        self.assertTrue(manager.config['version_control'])
    
    def test_initialization_with_custom_config(self):
        """Test that ModelManager initializes with custom configuration."""
        custom_config = {
            'storage_path': '/custom/path',
            'auto_update': False,
            'version_control': False
        }
        manager = self.ModelManager(custom_config)
        self.assertEqual(manager.config['storage_path'], '/custom/path')
        self.assertFalse(manager.config['auto_update'])
        self.assertFalse(manager.config['version_control'])
    
    def test_get_model_path(self):
        """Test getting the path to a model file."""
        manager = self.ModelManager({'storage_path': self.storage_path})
        model_name = 'test_model'
        version = '1.0.0'
        
        expected_path = os.path.join(
            self.storage_path,
            f"{model_name}_v{version}",
            f"{model_name}.bin"
        )
        
        result = manager._get_model_path(model_name, version)
        self.assertEqual(result, expected_path)
    
    def test_save_model_metadata(self):
        """Test saving model metadata to a file."""
        manager = self.ModelManager({'storage_path': self.storage_path})
        model_name = 'test_model'
        version = '1.0.0'
        metadata = {
            'version': version,
            'name': model_name,
            'description': 'A test model'
        }
        
        # Mock the file operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('json.dump') as mock_json_dump:
                manager._save_model_metadata(model_name, version, metadata)
                
                # Verify the file was opened in write mode
                mock_file.assert_called_once()
                
                # Verify the JSON dump was called with the correct metadata
                args, kwargs = mock_json_dump.call_args
                self.assertEqual(args[0], metadata)
    
    def test_load_model_metadata(self):
        """Test loading model metadata from a file."""
        manager = self.ModelManager({'storage_path': self.storage_path})
        model_name = 'test_model'
        version = '1.0.0'
        metadata = {
            'version': version,
            'name': model_name,
            'description': 'A test model'
        }
        
        # Mock the file operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('json.load', return_value=metadata):
                result = manager._load_model_metadata(model_name, version)
                self.assertEqual(result, metadata)
    
    def test_load_nonexistent_metadata(self):
        """Test loading metadata for a non-existent model."""
        manager = self.ModelManager({'storage_path': self.storage_path})
        
        # Mock the file operations to raise FileNotFoundError
        with patch('builtins.open', side_effect=FileNotFoundError):
            result = manager._load_model_metadata('nonexistent', '1.0.0')
            self.assertIsNone(result)
    
    def test_get_model_info(self):
        """Test getting information about a model."""
        # Set up test data
        version = '1.0.0'
        metadata = {
            'version': version,
            'name': 'model',  # Default model name
            'description': 'A test model'
        }
        
        # Create a manager with a fresh instance
        manager = self.ModelManager({'storage_path': self.storage_path})
        
        # Patch the methods we need to control
        with patch.object(manager, '_get_current_version', return_value=version) as mock_get_current_version, \
             patch.object(manager, '_load_metadata', return_value={'current_version': version}) as mock_load_metadata, \
             patch.object(manager, '_load_model_metadata', return_value=metadata) as mock_load_model_metadata:
            
            print("\n=== Starting test_get_model_info ===")
            
            # First test: no parameters
            print("\nTest 1: No parameters")
            result = manager.get_model_info()
            print(f"Result: {result}")
            print(f"Expected: {metadata}")
            print(f"_load_model_metadata calls: {mock_load_model_metadata.mock_calls}")
            
            # Verify the result and the call
            self.assertEqual(result, metadata)
            mock_load_model_metadata.assert_called_once_with('model', version)
            
            # Reset the mock for the next test
            mock_load_model_metadata.reset_mock()
            
            # Second test: explicit version only - should also use default model name 'model'
            print("\nTest 2: Explicit version")
            result = manager.get_model_info(version)
            print(f"Result: {result}")
            print(f"_load_model_metadata calls: {mock_load_model_metadata.mock_calls}")
            
            # Verify the result and the call
            self.assertEqual(result, metadata)
            mock_load_model_metadata.assert_called_once_with('model', version)
            
            # Reset the mock for the next test
            mock_load_model_metadata.reset_mock()
            
            # Third test: model_name:version format
            print("\nTest 3: model_name:version format")
            result = manager.get_model_info(f"custom_model:{version}")
            print(f"Result: {result}")
            print(f"_load_model_metadata calls: {mock_load_model_metadata.mock_calls}")
            
            # Verify the result and the call
            self.assertEqual(result, metadata)
            mock_load_model_metadata.assert_called_once_with('custom_model', version)
            
            print("\n=== Test completed successfully ===")
    
    def test_get_model_info_nonexistent(self):
        """Test getting information about a non-existent model."""
        manager = self.ModelManager({'storage_path': self.storage_path})
        
        # Test when no model is available
        with patch.object(manager, '_get_current_version', return_value=None), \
             patch.object(manager, '_load_model_metadata', return_value=None):
            result = manager.get_model_info()
            self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
