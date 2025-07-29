"""\nCore module for ATous Secure Network\n\nThis module contains the core functionality for model management,\nincluding federated learning updates and model versioning.\n"""

# Import directly from modules
from atous_sec_network.core.model_manager import ModelManager, FederatedModelUpdater
from atous_sec_network.core.model_metadata import ModelMetadata
from atous_sec_network.core.model_manager_impl import ModelManagerImpl

__all__ = ['ModelManager', 'FederatedModelUpdater', 'ModelMetadata', 'ModelManagerImpl']