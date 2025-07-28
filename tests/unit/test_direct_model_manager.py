"""Direct tests for model_manager.py module."""
import os
import sys
import pytest
import logging
from unittest.mock import MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import the module directly
import atous_sec_network.core.model_manager as model_manager_module

# Create a test class
class TestDirectModelManager:
    """Test the model_manager.py module directly."""
    
    def test_model_manager_class_exists(self):
        """Test that the ModelManager class exists in the module."""
        assert hasattr(model_manager_module, 'ModelManager')
        
        # Get the class
        model_manager_class = getattr(model_manager_module, 'ModelManager')
        
        # Check that it's a class
        assert isinstance(model_manager_class, type)
        
        # Create an instance
        config = {
            'model_path': '/tmp/test_model',
            'version_control': True,
            'auto_rollback': True
        }
        instance = model_manager_class(config)
        
        # Check that the instance has the expected attributes
        assert instance.config == config
        assert instance.model_path == config['model_path']
        assert instance.version_control == config['version_control']
        assert instance.auto_rollback == config['auto_rollback']
        assert instance.updater is None
        
    def test_federated_model_updater_class_exists(self):
        """Test that the FederatedModelUpdater class exists in the module."""
        assert hasattr(model_manager_module, 'FederatedModelUpdater')
        
        # Get the class
        federated_model_updater_class = getattr(model_manager_module, 'FederatedModelUpdater')
        
        # Check that it's a class
        assert isinstance(federated_model_updater_class, type)

if __name__ == '__main__':
    pytest.main(['-v', __file__])