"""Import fixtures from conftest_model_manager.py"""

# Import the certifi patch first to ensure it's applied before any other imports
from .conftest_patch import patch_requests_certs

from .conftest_model_manager import mock_federated_model_updater, model_manager_config, model_manager