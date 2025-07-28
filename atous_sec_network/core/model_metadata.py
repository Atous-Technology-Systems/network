"""
Model Metadata - Data classes for model metadata
"""
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class ModelMetadata:
    """Metadata for a machine learning model.
    
    Attributes:
        version: Version number of the model
        size: Size of the model in bytes
        checksum: SHA-256 checksum of the model file
        hardware_requirements: Dictionary of hardware requirements
        created_at: ISO format timestamp of when the model was created
        signature: Optional digital signature of the model
    """
    version: str
    size: int
    checksum: str
    hardware_requirements: Dict[str, Any]
    created_at: str
    signature: Optional[str] = None
