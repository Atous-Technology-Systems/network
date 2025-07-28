"""
Tests for ModelManager class with proper mocking.
"""
import os
import pytest

class TestModelManager:
    """Test cases for ModelManager class."""
    
    def test_initialization(self, model_manager, model_manager_config):
        """Test that ModelManager initializes with the correct configuration."""
        assert model_manager.config == model_manager_config
        assert model_manager.model_path == model_manager_config['model_path']
        assert model_manager.version_control == model_manager_config['version_control']
        assert model_manager.auto_rollback == model_manager_config['auto_rollback']
    
    def test_download_model(self, model_manager, mock_federated_model_updater):
        """Test downloading a model."""
        model_url = 'http://example.com/model.pt'
        model_path = '/tmp/test_model/model.pt'
        
        result = model_manager.download_model(model_url, model_path)
        
        assert result is True
        mock_federated_model_updater.download_model.assert_called_once_with(
            model_url, 
            model_path,
            checksum=None,
            timeout=60,
            max_retries=3
        )
    
    def test_apply_patch(self, model_manager, mock_federated_model_updater):
        """Test applying a model patch."""
        patch_data = {'version': '1.0.0', 'changes': 'test_changes'}
        
        result = model_manager.apply_patch(patch_data)
        
        assert result is True
        mock_federated_model_updater.apply_patch.assert_called_once_with(patch_data)
    
    def test_rollback(self, model_manager, mock_federated_model_updater):
        """Test rolling back to a previous version."""
        version = '0.9.0'
        
        result = model_manager.rollback(version)
        
        assert result is True
        mock_federated_model_updater.rollback.assert_called_once_with(version)
    
    def test_check_for_updates(self, model_manager, mock_federated_model_updater):
        """Test checking for model updates."""
        mock_federated_model_updater.check_for_updates.return_value = {'update_available': False}
        
        result = model_manager.check_for_updates()
        
        assert result == {'update_available': False}
        mock_federated_model_updater.check_for_updates.assert_called_once()

if __name__ == '__main__':
    pytest.main(['-v', __file__])
