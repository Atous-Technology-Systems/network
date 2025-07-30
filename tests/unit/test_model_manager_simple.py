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
# Force using ModelManager from model_manager.py for this test
from atous_sec_network.core.model_manager import ModelManager
print("Forcing use of ModelManager from model_manager.py for test_model_manager_simple.py")

def test_model_manager_initialization():
    """Test that ModelManager can be initialized."""
    # Create a test configuration with all required fields
    config = {
        'model_path': '/tmp/test_model',
        'version_control': True,
        'auto_rollback': True,
        'node_id': 'test_node',
        'storage_path': '/tmp/test_storage'
    }
    
    # Initialize the ModelManager
    manager = ModelManager(config)

    # Verify the manager was initialized with the correct config values
    for key, value in config.items():
        assert manager.config[key] == value

    # Verify specific attributes are set correctly
    assert manager.model_path == config['model_path']
    assert manager.version_control == config['version_control']
    assert manager.auto_rollback == config['auto_rollback']
    
    # Verify that updater is None as specified in the implementation
    assert manager.updater is None

def test_download_model():
    """Test the download_model method."""
    print("\n\n=== STARTING test_download_model ===\n")
    with patch('os.makedirs'):  # Mock os.makedirs to avoid actual directory creation
        with patch('atous_sec_network.core.model_manager.FederatedModelUpdater') as mock_updater_class:
            # Setup test data with all required fields
            config = {
                'model_path': '/tmp/test_model',
                'version_control': True,
                'auto_rollback': True,
                'node_id': 'test_node',
                'storage_path': '/tmp/test_storage'
            }
            print(f"Test config: {config}")
            model_url = 'http://example.com/model.pt'
            model_path = '/tmp/test_model/model.pt'

            # Create a mock instance and configure it
            mock_updater = MagicMock()
            mock_updater.download_model.return_value = True
            mock_updater_class.return_value = mock_updater
            print(f"Created mock_updater: {mock_updater}")

            # Initialize the ModelManager
            print("Initializing ModelManager...")
            manager = ModelManager(config)
            print(f"Manager initialized: {manager}")
            
            # Mock the _save_model_metadata method
            print("Patching _save_model_metadata...")
            with patch.object(manager, '_save_model_metadata') as mock_save_metadata:
                
                # Print debug info
                print(f"\nDEBUG: Before calling download_model")
                print(f"DEBUG: model_url = {model_url}")
                print(f"DEBUG: model_path = {model_path}")
                print(f"DEBUG: manager.updater = {manager.updater}")
                print(f"DEBUG: manager.__class__.__name__ = {manager.__class__.__name__}")
                print(f"DEBUG: manager.__module__ = {manager.__module__}")
                print(f"DEBUG: hasattr(manager, 'updater') = {hasattr(manager, 'updater')}")
                
                # Explicitly set updater to None to test the early return condition
                print("Setting manager.updater = None")
                manager.updater = None
                print(f"DEBUG: After setting manager.updater = None")
                print(f"DEBUG: manager.updater = {manager.updater}")
                print(f"DEBUG: hasattr(manager, 'updater') = {hasattr(manager, 'updater')}")
                
                # Call the method with test data
                print("\nCalling manager.download_model...")
                result = manager.download_model(model_url, model_path)
                print(f"DEBUG: download_model returned: {result}")
                print(f"DEBUG: type of result = {type(result)}")
                print(f"DEBUG: result is True? = {result is True}")
                print(f"DEBUG: result == True? = {result == True}")

                # Verify the result is True (early return condition)
                print("\nVerifying result...")
                print(f"DEBUG: assert result is True = {result is True}")
                assert result is True, f"Expected True but got {result} of type {type(result)}"
                
                # Since updater is None, these methods should not be called
                print("\nVerifying mock calls...")
                mock_updater.download_model.assert_not_called()
                mock_save_metadata.assert_not_called()
                
                print("\n=== FINISHED test_download_model ===\n")

def main():
    print("\n\n=== RUNNING test_model_manager_initialization ===\n")
    test_model_manager_initialization()
    print("\n\n=== RUNNING test_download_model ===\n")
    test_download_model()
    print("\n\n=== ALL TESTS PASSED ===\n")

if __name__ == '__main__':
    main()
