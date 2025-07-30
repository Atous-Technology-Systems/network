import os
import sys
import logging
from unittest.mock import MagicMock, patch

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Import the module to test
try:
    from atous_sec_network.core.model_manager_impl import ModelManager
    print("Using ModelManager from model_manager_impl.py")
except ImportError:
    # Fallback to regular ModelManager if impl version not available
    from atous_sec_network.core.model_manager import ModelManager
    print("Using ModelManager from model_manager.py")

# Create a test configuration with Windows paths
config = {
    'model_path': 'C:\\temp\\test_model',
    'version_control': True,
    'auto_rollback': True,
    'node_id': 'test_node',
    'storage_path': 'C:\\temp\\test_storage'
}

# Test URLs and paths (using Windows paths)
model_url = 'http://example.com/model.pt'
model_path = 'C:\\temp\\test_model\\model.pt'

# Create a mock for FederatedModelUpdater
with patch('atous_sec_network.core.model_manager_impl.FederatedModelUpdater') as mock_updater_class:
    # Create a mock instance
    mock_updater = MagicMock()
    mock_updater.download_model.return_value = True
    mock_updater_class.return_value = mock_updater

    # Mock the _get_latest_version method to return a version
    with patch('atous_sec_network.core.model_manager_impl.ModelManager._get_latest_version', return_value=1):
        # Initialize the ModelManager
        manager = ModelManager(config)
        
        # Print debug info
        print(f"\nDEBUG: Before calling download_model")
        print(f"DEBUG: model_url = {model_url}")
        print(f"DEBUG: model_path = {model_path}")
        print(f"DEBUG: manager.updater = {manager.updater}")
        print(f"DEBUG: manager.__class__.__name__ = {manager.__class__.__name__}")
        print(f"DEBUG: manager.__module__ = {manager.__module__}")
        
        # Mock the _update_metadata and _set_current_model methods
        with patch.object(manager, '_update_metadata') as mock_update_metadata, \
             patch.object(manager, '_set_current_model') as mock_set_current_model:
            
            # Call the method with test data
            result = manager.download_model(model_url, model_path)
            print(f"DEBUG: download_model returned: {result}")
            print(f"DEBUG: type of result = {type(result)}")
            print(f"DEBUG: result is True? = {result is True}")
            print(f"DEBUG: result == True? = {result == True}")
            
            # Verify the result
            print(f"DEBUG: assert result is True = {result is True}")
            
            # Verify the FederatedModelUpdater was called with the correct parameters
            try:
                mock_updater.download_model.assert_called_once_with(
                    source_url=model_url,
                    target_path=model_path,
                    checksum=None,
                    timeout=60,
                    headers={}
                )
                print("DEBUG: mock_updater.download_model was called with correct parameters")
            except AssertionError as e:
                print(f"DEBUG: mock_updater.download_model assertion failed: {e}")
            
            # Verify metadata was updated with default version
            model_name = os.path.basename(model_path)
            try:
                mock_update_metadata.assert_called_once_with(
                    model_name, '1.0.0', model_path, model_url
                )
                print("DEBUG: mock_update_metadata was called with correct parameters")
            except AssertionError as e:
                print(f"DEBUG: mock_update_metadata assertion failed: {e}")
            
            # Verify the model was set as current
            try:
                mock_set_current_model.assert_called_once_with('1.0.0', model_path)
                print("DEBUG: mock_set_current_model was called with correct parameters")
            except AssertionError as e:
                print(f"DEBUG: mock_set_current_model assertion failed: {e}")