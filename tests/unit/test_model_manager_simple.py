"""
Simple test file for ModelManager to help debug import issues.
"""
import os
import sys
import unittest
import pytest
from unittest.mock import MagicMock, patch

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import the module to test
# Import ModelManager from model_manager_impl
try:
    from atous_sec_network.core.model_manager_impl import ModelManager
except ImportError:
    # Fallback to regular ModelManager if impl version not available
    from atous_sec_network.core.model_manager import ModelManager

def test_model_manager_initialization():
    """Test that ModelManager can be initialized."""
    # Create a mock for FederatedModelUpdater
    with patch('atous_sec_network.core.model_manager_impl.FederatedModelUpdater') as mock_updater_class:
        # Create a test configuration with all required fields
        config = {
            'model_path': '/tmp/test_model',
            'version_control': True,
            'auto_rollback': True,
            'node_id': 'test_node',
            'storage_path': '/tmp/test_storage'
        }
        
        # Create a mock instance
        mock_updater = MagicMock()
        mock_updater_class.return_value = mock_updater

        # Initialize the ModelManager
        manager = ModelManager(config)

        # Verify the manager was initialized with the correct config values
        for key, value in config.items():
            assert manager.config[key] == value

        # Verify specific attributes are set correctly
        assert manager.model_path == config['model_path']
        assert manager.version_control == config['version_control']
        assert manager.auto_rollback == config['auto_rollback']
        
        # Verify the FederatedModelUpdater was initialized with correct parameters
        mock_updater_class.assert_called_once()
        call_args = mock_updater_class.call_args[1]
        assert call_args['node_id'] == config['node_id']
        assert call_args['model_path'] == config['model_path']

def test_download_model():
    """Test the download_model method."""
    with patch('os.makedirs'):  # Mock os.makedirs to avoid actual directory creation
        with patch('atous_sec_network.core.model_manager_impl.FederatedModelUpdater') as mock_updater_class:
            # Setup test data with all required fields
            config = {
                'model_path': '/tmp/test_model',
                'version_control': True,
                'auto_rollback': True,
                'node_id': 'test_node',
                'storage_path': '/tmp/test_storage'
            }
            model_url = 'http://example.com/model.pt'
            model_path = '/tmp/test_model/model.pt'

            # Create a mock instance and configure it
            mock_updater = MagicMock()
            mock_updater.download_model.return_value = True
            mock_updater_class.return_value = mock_updater

            # Mock the _get_latest_version method to return a version
            with patch('atous_sec_network.core.model_manager_impl.ModelManager._get_latest_version', return_value=1):
                # Initialize the ModelManager
                manager = ModelManager(config)
                
                # Mock the _update_metadata and _set_current_model methods
                with patch.object(manager, '_update_metadata') as mock_update_metadata, \
                     patch.object(manager, '_set_current_model') as mock_set_current_model:
                    
                    # Call the method with test data
                    result = manager.download_model(model_url, model_path)

                    # Verify the result
                    assert result is True
                    
                    # Verify the FederatedModelUpdater was called with the correct parameters
                    mock_updater.download_model.assert_called_once_with(
                        source_url=model_url,
                        target_path=model_path,
                        checksum=None,
                        timeout=60,
                        headers={}
                    )
                    
                    # Verify metadata was updated with default version
                    model_name = os.path.basename(model_path)
                    mock_update_metadata.assert_called_once_with(
                        model_name, '1.0.0', model_path, model_url
                    )
                    
                    # Verify the model was set as current
                    mock_set_current_model.assert_called_once_with('1.0.0', model_path)

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
