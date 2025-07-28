"""
ATous Secure Network - Core Module
Package containing secure network implementations with LoRa and P2P optimizations
"""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import submodules to make them available
import atous_sec_network.core
import atous_sec_network.security
import atous_sec_network.network
import atous_sec_network.ml

# Use lazy imports to avoid circular import issues
def _import_model_manager():
    from atous_sec_network.core.model_manager_impl import ModelManager
    return ModelManager

def _import_model_metadata():
    from atous_sec_network.core.model_metadata import ModelMetadata
    return ModelMetadata

def _import_federated_model_updater():
    from atous_sec_network.core.model_manager import FederatedModelUpdater
    return FederatedModelUpdater

__version__ = "2.0.0"

# Define __all__ to explicitly specify what gets imported with 'from atous_sec_network import *'
__all__ = [
    'ModelManager',
    'ModelMetadata',
    'FederatedModelUpdater',
    '_import_model_manager',
    '_import_model_metadata',
    '_import_federated_model_updater'
]
