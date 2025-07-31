"""
Test ModelManager Implementation

Comprehensive tests for the ModelManager class.
"""
import unittest
from unittest.mock import patch, MagicMock, mock_open, ANY
import tempfile
import os
import json
import shutil
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Mock dependencies before importing the module
import atous_sec_network.core.model_manager as model_manager
from atous_sec_network.core.model_metadata import ModelMetadata
# Import ModelManager from model_manager_impl
try:
    from atous_sec_network.core.model_manager_impl import ModelManager
except ImportError:
    # Fallback to regular ModelManager if impl version not available
    from atous_sec_network.core.model_manager import ModelManager

class TestModelManager(unittest.TestCase):
    """Test cases for ModelManager class."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()
        self.model_dir = os.path.join(self.test_dir, 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Default config
        self.config = {
            'storage_path': self.model_dir,
            'max_versions': 5,
            'model_name': 'test_model',
            'node_id': 'test_node'
        }
        
        # Mock FederatedModelUpdater
        self.mock_updater = MagicMock()
        self.mock_updater.current_version = '1.0.0'
        self.mock_updater.model_path = os.path.join(self.model_dir, '1.0.0', 'model.bin')
        
        # Create a mock model file
        os.makedirs(os.path.join(self.model_dir, '1.0.0'), exist_ok=True)
        with open(os.path.join(self.model_dir, '1.0.0', 'model.bin'), 'wb') as f:
            f.write(b'test model data')
        
        # Patch the FederatedModelUpdater class
        self.updater_patcher = patch('atous_sec_network.core.model_manager_impl.FederatedModelUpdater', 
        return_value=self.mock_updater)
        self.mock_updater_class = self.updater_patcher.start()
        
        # Initialize the manager
        self.manager = ModelManager(self.config)
    
    def tearDown(self):
        """Clean up after tests."""
        self.updater_patcher.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test that ModelManager initializes correctly."""
        self.assertEqual(self.manager.model_dir, self.model_dir)
        self.assertEqual(self.manager.max_versions, 5)
        self.assertEqual(self.manager.model_name, 'test_model')
        self.mock_updater_class.assert_called_once()
    
    def test_list_available_versions(self):
        """Test listing available model versions."""
        # Create some version directories
        for version in ['1.0.0', '1.1.0', '2.0.0']:
            os.makedirs(os.path.join(self.model_dir, version), exist_ok=True)
        
        versions = self.manager.list_available_versions()
        self.assertEqual(set(versions), {'1.0.0', '1.1.0', '2.0.0'})
    
    def test_get_current_version(self):
        """Test getting the current model version."""
        self.assertEqual(self.manager.get_current_version(), '1.0.0')
    
    def test_get_system_metrics(self):
        """Test getting system metrics."""
        with patch('psutil.cpu_percent', return_value=50.0), \
             patch('psutil.virtual_memory') as mock_vm, \
             patch('psutil.disk_usage') as mock_disk:
            
            mock_vm.return_value.percent = 75.5
            mock_vm.return_value.available = 1024 * 1024 * 1024  # 1GB
            mock_disk.return_value.percent = 60.0
            
            metrics = self.manager.get_system_metrics()
            
            self.assertEqual(metrics['cpu_usage'], 50.0)
            self.assertEqual(metrics['memory_usage'], 75.5)
            self.assertEqual(metrics['available_memory'], 1024 * 1024 * 1024)
            self.assertEqual(metrics['disk_usage'], 60.0)
          
        
        result = self.manager.rollback_version(old_version)
        
        # Verify results
        self.assertTrue(result)
        self.assertEqual(self.manager._get_current_version(), old_version)
        self.assertTrue(os.path.islink(current_model))
        self.assertEqual(os.path.realpath(current_model), old_model)
    
    def test_cleanup_old_versions(self):
        """Test cleaning up old model versions."""
        # Create test versions
        versions = ['1.0.0', '2.0.0', '3.0.0', '4.0.0']
        
        # Create test files and metadata
        for version in versions:
            # Create directories without 'v' prefix to match list_available_versions expectation
            version_dir = os.path.join(self.config['storage_path'], version)
            os.makedirs(version_dir, exist_ok=True)
            model_file = os.path.join(version_dir, 'model.bin')
            with open(model_file, 'wb') as f:
                f.write(f'model data {version}'.encode())
            
            self.manager.metadata[version] = {
                'version': version,
                'path': model_file,
                'name': 'test_model',
                'size': 1024
            }
        
        # Set current version
        self.manager.metadata['current_version'] = '4.0.0'
        
        # Test cleanup (keep 2 most recent versions)
        removed = self.manager.cleanup_old_versions(keep_versions=2)
        
        # Verify results
        self.assertEqual(removed, 2)  # Should remove 2 oldest versions
        self.assertEqual(len(self.manager.list_available_versions()), 2)
        self.assertNotIn('1.0.0', self.manager.metadata)
        self.assertNotIn('2.0.0', self.manager.metadata)
        self.assertIn('3.0.0', self.manager.metadata)
        self.assertIn('4.0.0', self.manager.metadata)
    
    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    @patch('psutil.disk_usage')
    @patch('psutil.net_connections')
    def test_get_system_metrics(self, mock_net, mock_disk, mock_mem, mock_cpu):
        """Test getting system metrics."""
        # Setup mocks
        mock_cpu.return_value = 25.5
        
        mem = MagicMock()
        mem.total = 8 * 1024 * 1024 * 1024  # 8GB
        mem.available = 4 * 1024 * 1024 * 1024  # 4GB
        mem.percent = 50.0
        mem.used = 4 * 1024 * 1024 * 1024
        mem.free = 4 * 1024 * 1024 * 1024
        mock_mem.return_value = mem
        
        disk = MagicMock()
        disk.total = 100 * 1024 * 1024 * 1024  # 100GB
        disk.used = 50 * 1024 * 1024 * 1024  # 50GB
        disk.free = 50 * 1024 * 1024 * 1024
        disk.percent = 50.0
        mock_disk.return_value = disk
        
        mock_net.return_value = [MagicMock(), MagicMock()]  # 2 connections
        
        # Get metrics
        metrics = self.manager.get_system_metrics()
        
        # Verify results
        self.assertIn('cpu', metrics)
        self.assertIn('memory', metrics)
        self.assertIn('disk', metrics)
        self.assertIn('network', metrics)
        self.assertIn('timestamp', metrics)
        
        self.assertEqual(metrics['cpu']['percent'], 25.5)
        self.assertEqual(metrics['memory']['total'], 8 * 1024 * 1024 * 1024)
        self.assertEqual(metrics['disk']['total'], 100 * 1024 * 1024 * 1024)
        self.assertEqual(metrics['network']['connections'], 2)

if __name__ == '__main__':
    unittest.main()
