"""Patch for certifi module to fix the 'where' import issue."""
import sys
import os
import types

# Create a certifi module with a where function before any imports happen
def patch_certifi():
    # Create a simple module with a where function
    def where():
        return os.path.join(os.path.dirname(__file__), 'cacert.pem')
    
    # Create a certifi module
    certifi_module = types.ModuleType('certifi')
    certifi_module.where = where
    
    # Add it to sys.modules
    sys.modules['certifi'] = certifi_module
    
    # Create a certs module for requests
    certs_module = types.ModuleType('certs')
    certs_module.where = where
    
    # Add it to sys.modules
    sys.modules['requests.certs'] = certs_module

# Apply the patch immediately when this module is imported
patch_certifi()

# Now we can safely import these modules
import pytest
import urllib3
import requests
from unittest.mock import patch

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Patch requests to disable SSL verification
original_get = requests.get
def patched_get(*args, **kwargs):
    kwargs['verify'] = False
    return original_get(*args, **kwargs)

requests.get = patched_get

@pytest.fixture(autouse=True, scope="session")
def patch_requests_certs():
    """This fixture ensures the patch remains active during testing."""
    yield
    
    # Clean up is optional but good practice
    requests.get = original_get