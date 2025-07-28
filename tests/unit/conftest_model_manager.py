"""
Test configuration for ModelManager tests.
This file contains fixtures and mocks specifically for ModelManager tests.
"""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

@pytest.fixture
def mock_federated_model_updater():
    """Fixture to mock the FederatedModelUpdater class."""
    with patch('atous_sec_network.core.model_manager.FederatedModelUpdater') as mock_updater:
        # Configure the mock instance
        mock_instance = MagicMock()
        mock_updater.return_value = mock_instance
        
        # Set up return values for methods
        mock_instance.download_model.return_value = True
        mock_instance.apply_patch.return_value = True
        mock_instance.rollback.return_value = True
        mock_instance.check_for_updates.return_value = False
        
        yield mock_instance

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
    from atous_sec_network.core.model_manager_impl import ModelManager
    return ModelManager(model_manager_config)
