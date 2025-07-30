"""Base class for model managers to ensure consistent interface."""

from abc import ABC, abstractmethod
from typing import Dict, Optional, Any, Union


class ModelManagerBase(ABC):
    """
    Abstract base class defining the interface for model managers.
    
    This ensures that all model manager implementations follow the same interface,
    making them interchangeable and easier to test.
    """
    
    @abstractmethod
    def download_model(self, url: str, path: Optional[str] = None, 
                      checksum: Optional[str] = None, **kwargs) -> bool:
        """
        Download a model from the specified URL.
        
        Args:
            url: URL to download the model from
            path: Path to save the model to (optional)
            checksum: Optional checksum to verify the downloaded model
            **kwargs: Additional arguments for the download process
            
        Returns:
            bool: True if download was successful, False otherwise
        """
        pass
        
    @abstractmethod
    def check_for_updates(self, server_url: str) -> Dict[str, Any]:
        """
        Check for available model updates.
        
        Args:
            server_url: URL of the update server
            
        Returns:
            Dict[str, Any]: Update information, including whether an update is available
        """
        pass
        
    @abstractmethod
    def apply_patch(self, patch_data: Dict[str, Any]) -> bool:
        """
        Apply a patch to the current model.
        
        Args:
            patch_data: Dictionary containing patch information
            
        Returns:
            bool: True if patch was successfully applied, False otherwise
        """
        pass
        
    @abstractmethod
    def rollback(self, version: str) -> bool:
        """
        Roll back to a previous model version.
        
        Args:
            version: The version to roll back to
            
        Returns:
            bool: True if rollback was successful, False otherwise
        """
        pass