"""
Test cases for model integrity verification in ModelManager.

This test file focuses on testing the model integrity verification functionality,
which is critical for ensuring the correctness of model updates and rollbacks.
"""
import os
import sys
import unittest
import tempfile
import shutil
import hashlib
from unittest.mock import MagicMock, patch, mock_open

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Mock external dependencies
sys.modules['RPi'] = MagicMock()
sys.modules['RPi.GPIO'] = MagicMock()
sys.modules['serial'] = MagicMock()
sys.modules['serial.tools'] = MagicMock()
sys.modules['serial.tools.list_ports'] = MagicMock()

class TestModelIntegrity(unittest.TestCase):
    """Test model integrity verification functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.model_path = os.path.join(self.test_dir, 'test_model.bin')
        self.storage_path = os.path.join(self.test_dir, 'model_storage')
        
        # Create necessary directories
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Create a test model file with known content and checksum
        self.test_data = b'test model data for integrity check'
        with open(self.model_path, 'wb') as f:
            f.write(self.test_data)
        
        # Calculate the expected checksum
        self.expected_checksum = hashlib.sha256(self.test_data).hexdigest()
        
        # Mock FederatedModelUpdater
        self.mock_updater = MagicMock()
        self.mock_updater_class = MagicMock(return_value=self.mock_updater)
        
        # Patch the FederatedModelUpdater import
        self.patcher = patch('atous_sec_network.core.model_manager_impl.FederatedModelUpdater', 
                           self.mock_updater_class)
        self.patcher.start()
        
        # Import ModelManager after patching
        from atous_sec_network.core.model_manager_impl import ModelManager
        self.ModelManager = ModelManager
    
    def tearDown(self):
        """Clean up after tests."""
        self.patcher.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_verify_integrity_valid_checksum(self):
        """Test verifying a model with a valid checksum."""
        manager = self.ModelManager({
            'storage_path': self.storage_path,
            'version_control': True
        })
        
        # Create a metadata file with the correct checksum
        metadata = {
            'version': '1.0.0',
            'checksum': self.expected_checksum,
            'timestamp': '2023-01-01T00:00:00',
            'size': len(self.test_data)
        }
        
        # Test with valid checksum
        with patch('json.load', return_value=metadata):
            with patch('builtins.open', mock_open(read_data=self.test_data)):
                result = manager._verify_model_integrity(self.model_path, '1.0.0')
                self.assertTrue(result)
    
    def test_verify_integrity_invalid_checksum(self):
        """Test verifying a model with an invalid checksum."""
        manager = self.ModelManager({
            'storage_path': self.storage_path,
            'version_control': True
        })
        
        # Create a metadata file with an incorrect checksum
        metadata = {
            'version': '1.0.0',
            'checksum': 'invalid_checksum_1234567890abcdef',
            'timestamp': '2023-01-01T00:00:00',
            'size': len(self.test_data)
        }
        
        # Test with invalid checksum
        with patch('os.path.exists', return_value=True):  # Make metadata file appear to exist
            with patch('json.load', return_value=metadata):
                with patch('builtins.open', mock_open(read_data=self.test_data)):
                    result = manager._verify_model_integrity(self.model_path, '1.0.0')
                    self.assertFalse(result)
    
    def test_verify_integrity_missing_metadata(self):
        """Test verifying a model with missing metadata."""
        manager = self.ModelManager({
            'storage_path': self.storage_path,
            'version_control': True
        })
        
        # Test with missing metadata file
        with patch('os.path.exists', return_value=False):
            result = manager._verify_model_integrity(self.model_path, '1.0.0')
            self.assertFalse(result)
    
    def test_verify_integrity_corrupted_file(self):
        """Test verifying a corrupted model file."""
        manager = self.ModelManager({
            'storage_path': self.storage_path,
            'version_control': True
        })
        
        # Create a metadata file with the correct checksum
        metadata = {
            'version': '1.0.0',
            'checksum': self.expected_checksum,
            'timestamp': '2023-01-01T00:00:00',
            'size': len(self.test_data)
        }
        
        # Test with corrupted file data
        corrupted_data = b'corrupted model data'
        with patch('os.path.exists', return_value=True):  # Make metadata file appear to exist
            with patch('json.load', return_value=metadata):
                with patch('builtins.open', mock_open(read_data=corrupted_data)):
                    result = manager._verify_model_integrity(self.model_path, '1.0.0')
                    self.assertFalse(result)
    
    def test_verify_integrity_size_mismatch(self):
        """Test verifying a model with incorrect file size."""
        manager = self.ModelManager({
            'storage_path': self.storage_path,
            'version_control': True
        })
        
        # Create a metadata file with incorrect size
        metadata = {
            'version': '1.0.0',
            'checksum': self.expected_checksum,
            'timestamp': '2023-01-01T00:00:00',
            'size': len(self.test_data) + 100  # Incorrect size
        }
        
        # Test with size mismatch
        with patch('os.path.exists', return_value=True):  # Make metadata file appear to exist
            with patch('json.load', return_value=metadata):
                with patch('builtins.open', mock_open(read_data=self.test_data)):
                    result = manager._verify_model_integrity(self.model_path, '1.0.0')
                    self.assertFalse(result)
    
    def test_verify_integrity_version_mismatch(self):
        """Test verifying a model with version mismatch."""
        manager = self.ModelManager({
            'storage_path': self.storage_path,
            'version_control': True
        })
        
        # Create a metadata file with version mismatch
        metadata = {
            'version': '2.0.0',  # Different version
            'checksum': self.expected_checksum,
            'timestamp': '2023-01-01T00:00:00',
            'size': len(self.test_data)
        }
        
        # Test with version mismatch
        with patch('os.path.exists', return_value=True):  # Make metadata file appear to exist
            with patch('json.load', return_value=metadata):
                with patch('builtins.open', mock_open(read_data=self.test_data)):
                    result = manager._verify_model_integrity(self.model_path, '1.0.0')
                    self.assertFalse(result)
    
    def test_verify_integrity_io_error(self):
        """Test handling of IOError during integrity check."""
        manager = self.ModelManager({
            'storage_path': self.storage_path,
            'version_control': True
        })
        
        # Test with IOError when reading the file
        with patch('builtins.open', side_effect=IOError("File read error")):
            result = manager._verify_model_integrity(self.model_path, '1.0.0')
            self.assertFalse(result)
    
    def test_verify_integrity_json_error(self):
        """Test handling of JSON decode error during integrity check."""
        manager = self.ModelManager({
            'storage_path': self.storage_path,
            'version_control': True
        })
        
        # Test with JSON decode error
        with patch('os.path.exists', return_value=True):  # Make metadata file appear to exist
            with patch('json.load', side_effect=ValueError("Invalid JSON")):
                with patch('builtins.open', mock_open(read_data=self.test_data)):
                    result = manager._verify_model_integrity(self.model_path, '1.0.0')
                    self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
