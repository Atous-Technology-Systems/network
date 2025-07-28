"""
Core module for ATous Secure Network

This module contains the core functionality for model management,
including federated learning updates and model versioning.
"""

from .model_manager_impl import ModelManager
from .model_manager import FederatedModelUpdater
from .model_metadata import ModelMetadata

__all__ = ['ModelManager', 'FederatedModelUpdater', 'ModelMetadata'] 