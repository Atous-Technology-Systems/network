"""Test model manager dependencies and functionality"""
import unittest
from unittest.mock import patch, MagicMock
import os
import tempfile

class TestModelManagerDependencies(unittest.TestCase):
    """Test ModelManager dependencies"""

    def test_requests_import(self):
        """Test that requests module can be imported"""
        import requests
        self.assertIsNotNone(requests)
        self.assertTrue(hasattr(requests, 'get'))
        self.assertTrue(hasattr(requests, 'post'))

    def test_bsdiff4_import(self):
        """Test that bsdiff4 module can be imported"""
        import bsdiff4
        self.assertIsNotNone(bsdiff4)
        self.assertTrue(hasattr(bsdiff4, 'file_patch'))
        self.assertTrue(hasattr(bsdiff4, 'file_diff'))

    def test_psutil_import(self):
        """Test that psutil module can be imported"""
        import psutil
        self.assertIsNotNone(psutil)
        self.assertTrue(hasattr(psutil, 'cpu_percent'))
        self.assertTrue(hasattr(psutil, 'virtual_memory'))

    @patch('requests.Session')
    def test_model_download(self, mock_session):
        """Test model download functionality"""
        from atous_sec_network.core.model_manager import ModelManager
        
        # Setup mock session
        mock_session_instance = mock_session.return_value
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"mock_model_data"
        mock_session_instance.get.return_value = mock_response

        # Create temporary directory for test
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ModelManager({
                'storage_path': tmpdir,
                'version_control': True,
                'auto_rollback': True
            })
            
            # Test download
            success = manager.download_model('test_model', '1.0.0')
            self.assertTrue(success)
            
            # Verify request was made using the session
            mock_session_instance.get.assert_called_once()

    @patch('psutil.virtual_memory')
    def test_resource_check(self, mock_vmem):
        """Test resource checking functionality"""
        from atous_sec_network.core.model_manager import ModelManager
        
        # Mock memory info
        mock_vmem.return_value = MagicMock(
            total=16000000000,  # 16GB
            available=8000000000  # 8GB
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ModelManager({
                'storage_path': tmpdir,
                'version_control': True,
                'auto_rollback': True
            })
            
            # Test resource check
            has_resources = manager.check_resources(required_memory=4000000000)  # 4GB
            self.assertTrue(has_resources)

if __name__ == '__main__':
    unittest.main()
