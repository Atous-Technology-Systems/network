"""
Model Manager - High-level interface for model management

This module provides a high-level interface for managing machine learning models,
including versioning, updates, and optimizations. It wraps the FederatedModelUpdater
class to provide a more user-friendly API.
"""
import os
import logging
import tempfile
import json
import time
from typing import Dict, List, Optional, Tuple, Any, Union
from pathlib import Path
import requests
import psutil
import shutil
import hashlib
from datetime import datetime, timedelta

from atous_sec_network.core.model_metadata import ModelMetadata

# Try to import FederatedModelUpdater, but create a mock if it fails
try:
    from atous_sec_network.core.model_manager import FederatedModelUpdater
except ImportError:
    # Create a mock FederatedModelUpdater for testing
    import logging
    class FederatedModelUpdater:
        """Mock FederatedModelUpdater for testing"""
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger(__name__)
        
        def download_model(self, *args, **kwargs):
            return True
            
        def apply_patch(self, *args, **kwargs):
            return True
            
        def rollback(self, *args, **kwargs):
            return True
            
        def check_for_updates(self, *args, **kwargs):
            return False

# No need to import ModelManager since it's defined in this file

# This file is kept for backward compatibility
# The ModelManager class has been moved to model_manager.py

# Legacy implementation - for reference only
class ModelManagerImpl:
    """
    High-level interface for managing machine learning models.
    
    This class provides a simplified interface for common model management tasks
    including downloading, updating, and optimizing models. It wraps the
    FederatedModelUpdater class to provide a more user-friendly API.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the ModelManager with the given configuration.
        
        Args:
            config: Configuration dictionary. Supported keys:
                - node_id: Unique identifier for this node (default: auto-generated)
                - storage_path: Base directory for model storage (default: 'models')
                - auto_update: Whether to automatically check for updates (default: True)
                - version_control: Whether to maintain version history (default: True)
                - auto_rollback: Whether to automatically rollback failed updates (default: True)
                - max_versions: Maximum number of versions to keep (default: 5)
        """
        self.config = {
            'node_id': f"node_{os.urandom(4).hex()}",
            'storage_path': 'models',
            'auto_update': True,
            'version_control': True,
            'auto_rollback': True,
            'max_versions': 5,
            **(config or {})
        }
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
        
        # Ensure storage directory exists
        os.makedirs(self.config['storage_path'], exist_ok=True)
        
        # Expose config values as attributes for easier access
        self.version_control = self.config['version_control']
        self.auto_rollback = self.config['auto_rollback']
        self.max_versions = self.config['max_versions']
        self.model_name = self.config.get('model_name', 'default_model')
        
        # Initialize FederatedModelUpdater
        # Use the provided model_path if specified, otherwise use default
        self.model_path = self.config.get('model_path', os.path.join(self.config['storage_path'], 'current_model.bin'))
        self.backup_dir = os.path.join(os.path.dirname(self.model_path), 'backups')
        
        # Ensure the model directory exists
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Initialize FederatedModelUpdater with proper parameters
        self.updater = FederatedModelUpdater(
            node_id=self.config['node_id'],
            current_version=self._get_latest_version(),
            model_path=self.model_path,
            backup_dir=self.backup_dir
        )
        
        # Load model metadata
        self.metadata_file = os.path.join(self.config['storage_path'], 'metadata.json')
        self.metadata = self._load_metadata()
    
    def _get_model_path(self, model_name: str, version: str) -> str:
        """
        Get the filesystem path for a model with the given name and version.
        
        Args:
            model_name: Name of the model
            version: Version of the model
            
        Returns:
            str: Full path to the model file
        """
        # Create a versioned directory for the model
        version_dir = os.path.join(
            self.config['storage_path'],
            f"{model_name}_v{version}"
        )
        
        # Return the path to the model file
        return os.path.join(version_dir, f"{model_name}.bin")
    
    def _save_model_metadata(self, model_name: str, version: str, metadata: Dict[str, Any]) -> None:
        """
        Save metadata for a model.
        
        Args:
            model_name: Name of the model
            version: Version of the model
            metadata: Dictionary containing model metadata
        """
        # Create the versioned directory if it doesn't exist
        version_dir = os.path.join(
            self.config['storage_path'],
            f"{model_name}_v{version}"
        )
        os.makedirs(version_dir, exist_ok=True)
        
        # Add/update common metadata fields
        metadata.update({
            'name': model_name,
            'version': version,
            'last_updated': datetime.utcnow().isoformat()
        })
        
        # Save the metadata to a JSON file
        metadata_path = os.path.join(version_dir, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.debug(f"Saved metadata for {model_name} v{version} to {metadata_path}")
    
    def _load_model_metadata(self, model_name: str, version: str) -> Optional[Dict[str, Any]]:
        """
        Load metadata for a model.
        
        Args:
            model_name: Name of the model
            version: Version of the model
            
        Returns:
            Optional[Dict[str, Any]]: Model metadata if found, None otherwise
        """
        metadata_path = os.path.join(
            self.config['storage_path'],
            f"{model_name}_v{version}",
            'metadata.json'
        )
        
        try:
            with open(metadata_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.warning(f"Failed to load metadata for {model_name} v{version}: {str(e)}")
            return None
    
    def _get_current_version(self) -> Optional[str]:
        """
        Get the current version of the model.
        
        Returns:
            str: Current version string or None if not available
        """
        # First check metadata
        if hasattr(self, 'metadata') and self.metadata and 'current_version' in self.metadata:
            return self.metadata['current_version']
            
        # Fall back to updater's current version if available
        if hasattr(self, 'updater') and hasattr(self.updater, 'current_version'):
            return self.updater.current_version
            
        return None
    
    def get_model_info(self, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific model version.
        
        Args:
            version: Version string (default: current version)
            
        Returns:
            Dict with model information or None if not found
        """
        print("\n=== ENTERING get_model_info ===")
        print(f"Input version: {version}")
        
        if version is None:
            print("No version provided, getting current version...")
            current_version = self._get_current_version()
            print(f"Got current version: {current_version}")
            version = current_version
            if version is None:
                print("No current version available, returning None")
                return None
        
        print(f"Processing version: {version}")
        
        # Check if version is in the format 'model_name:version'
        if ':' in version:
            try:
                model_name, version = version.split(':', 1)
                print(f"Extracted model_name={model_name}, version={version}")
                print(f"Calling _load_model_metadata('{model_name}', '{version}')...")
                result = self._load_model_metadata(model_name, version)
                print(f"_load_model_metadata returned: {result}")
                return result
            except (ValueError, AttributeError) as e:
                warning_msg = f"Invalid model identifier format: {version}, error: {str(e)}"
                print(f"ERROR: {warning_msg}")
                self.logger.warning(warning_msg)
                return None
        else:
            # For backward compatibility, assume the model name is 'model'
            print(f"No model name provided, using default 'model' with version: {version}")
            print(f"Calling _load_model_metadata('model', '{version}')...")
            result = self._load_model_metadata('model', version)
            print(f"_load_model_metadata returned: {result}")
            print("=== EXITING get_model_info ===\n")
            return result
    
    def get_available_versions(self, model_name: str) -> List[str]:
        """
        Get a list of available versions for a model.
        
        Args:
            model_name: Name of the model
            
        Returns:
            List[str]: List of version strings
        """
        # This is a basic implementation that scans the storage directory
        # In a production environment, you might want to cache this or use a database
        versions = []
        pattern = f"{model_name}_v*"
        
        try:
            for entry in os.listdir(self.config['storage_path']):
                if entry.startswith(f"{model_name}_v") and os.path.isdir(os.path.join(self.config['storage_path'], entry)):
                    version = entry[len(f"{model_name}_v"):]
                    versions.append(version)
        except FileNotFoundError:
            pass
            
        return sorted(versions)
    
    def download_model(self, source_url: str, model_path: str, **kwargs) -> bool:
        """
        Download a model from the given URL.
        
        Args:
            source_url: URL to download the model from
            model_path: Local path to save the downloaded model
            **kwargs: Additional arguments for the download:
                - checksum: Expected checksum of the file (optional)
                - timeout: Request timeout in seconds (default: 60)
                - headers: HTTP headers for the request (optional)
                
        Returns:
            bool: True if download was successful, False otherwise
        """
        try:
            self.logger.info(f"Downloading model from {source_url} to {model_path}")
            
            # Use the FederatedModelUpdater to handle the download
            # Use the FederatedModelUpdater to handle the download
            success = self.updater.download_model(
                source_url=source_url,
                target_path=model_path,
                checksum=kwargs.get('checksum'),
                timeout=kwargs.get('timeout', 60),
                headers=kwargs.get('headers', {})
            )
            
            if success:
                self.logger.info(f"Successfully downloaded model to {model_path}")
                
                # Update metadata
                model_name = os.path.basename(model_path)
                version = "1.0.0"  # Default version, can be updated based on actual version
                self._update_metadata(model_name, version, model_path, source_url)
                
                # If this is the first model or auto_update is True, set as current
                if not os.path.exists(self.model_path) or self.config['auto_update']:
                    self._set_current_model(version, model_path)
            else:
                self.logger.error(f"Failed to download model from {source_url}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to download model: {e}")
            if os.path.exists(model_path):
                os.remove(model_path)
            return False
    def check_for_updates(self, aggregation_server: str) -> bool:
        """
        Check for model updates from the aggregation server.
        
        Args:
            aggregation_server: Base URL of the aggregation server
                
        Returns:
            bool: True if an update was applied, False otherwise
        """
        try:
            return self.updater.check_for_updates(aggregation_server)
        except Exception as e:
            self.logger.error(f"Failed to check for updates: {e}")
            return False
    
    def list_available_versions(self) -> List[str]:
        """
        List all available model versions.
        
        Returns:
            List of version strings, sorted newest first
        """
        def version_key(v: str) -> List[Union[int, str]]:
            try:
                return [int(n) for n in v.split('.')]
            except (ValueError, AttributeError):
                return []
        
        # Get versions from metadata
        versions = set()
        if hasattr(self, 'metadata') and self.metadata:
            versions.update(v for v in self.metadata.keys() if v.replace('.', '').isdigit())
        
        # Also check the filesystem for version directories
        try:
            for entry in os.listdir(self.config['storage_path']):
                if os.path.isdir(os.path.join(self.config['storage_path'], entry)):
                    # Check for directories named 'vX.Y.Z' or 'modelname_vX.Y.Z'
                    if entry.startswith('v') and all(c.isdigit() or c == '.' for c in entry[1:]):
                        versions.add(entry[1:])  # Remove the 'v' prefix
                    elif '_v' in entry and all(c.isdigit() or c == '.' for c in entry.split('_v')[-1]):
                        versions.add(entry.split('_v')[-1])
        except (FileNotFoundError, OSError) as e:
            self.logger.warning(f"Error scanning for version directories: {e}")
        
        # Sort versions with newest first
        return sorted(versions, key=version_key, reverse=True)
    
    def rollback_version(self, version: str) -> bool:
        """
        Roll back to a previous model version.
        
        Args:
            version: Version to roll back to
            
        Returns:
            bool: True if rollback was successful, False otherwise
        """
        try:
            model_info = self.metadata.get(version)
            if not model_info:
                self.logger.error(f"Version {version} not found in metadata")
                return False
            
            model_path = model_info.get('path')
            if not model_path:
                self.logger.error(f"No path found for version {version}")
                return False
                
            if not os.path.exists(model_path):
                self.logger.error(f"Model file not found at {model_path}")
                return False
            
            # Create a backup of the current model if it exists
            backup_path = None
            if os.path.exists(self.model_path):
                backup_path = f"{self.model_path}.{int(time.time())}.bak"
                try:
                    shutil.copy2(self.model_path, backup_path)
                    self.logger.debug(f"Created backup at {backup_path}")
                except Exception as e:
                    self.logger.error(f"Failed to create backup: {e}")
                    return False
            
            try:
                # Use _set_current_model to handle the actual file operations
                if not self._set_current_model(version, model_path):
                    raise RuntimeError("Failed to set current model")
                
                # Verify the rollback was successful
                if not os.path.exists(self.model_path):
                    raise RuntimeError("Model file was not created")
                
                # Verify the content matches the target version
                if os.path.getsize(self.model_path) != os.path.getsize(model_path):
                    raise RuntimeError("Model file size mismatch after rollback")
                
                # Update the current version in the updater
                self.updater.current_version = int(version.split('.')[0])  # Extract major version
                
                self.logger.info(f"Successfully rolled back to version {version}")
                return True
                
            except Exception as e:
                self.logger.error(f"Rollback failed: {e}")
                
                # Attempt to restore from backup if available
                if backup_path and os.path.exists(backup_path):
                    try:
                        shutil.move(backup_path, self.model_path)
                        self.logger.info("Restored from backup after failed rollback")
                    except Exception as restore_error:
                        self.logger.error(f"Failed to restore from backup: {restore_error}")
                
                return False
            
        except Exception as e:
            self.logger.error(f"Unexpected error during rollback: {e}", exc_info=True)
            return False
    
    def cleanup_old_versions(self, keep_versions: Optional[int] = None) -> int:
        """
        Remove old model versions to save disk space.
        
        Args:
            keep_versions: Number of most recent versions to keep
                          (default: from config)
                          
        Returns:
            int: Number of versions removed
            
        Note:
            - Never removes the currently active version
            - Preserves at least one version even if keep_versions is 0
        """
        if keep_versions is None:
            keep_versions = self.max_versions
            
        # Ensure we keep at least one version
        keep_versions = max(1, keep_versions)
        
        # Get all versions and sort them (newest first)
        versions = self.list_available_versions()
        if not versions:
            return 0
            
        # Sort versions (newest first)
        versions = sorted(versions, reverse=True, key=lambda v: [int(n) for n in v.split('.')])
        
        # Get current version
        current_version = self._get_current_version()
        
        # Don't remove if we don't have more than keep_versions
        if len(versions) <= keep_versions:
            return 0
            
        # Get versions to remove (oldest first, exclude current version)
        versions_to_remove = []
        
        # Start from the end (oldest) and work backwards
        for version in reversed(versions):
            if version == current_version:
                continue
                
            if len(versions) - len(versions_to_remove) > keep_versions:
                versions_to_remove.append(version)
            else:
                break
                
        # Remove the versions
        removed = 0
        for version in versions_to_remove:
            # Get model path from metadata
            model_info = self.metadata.get(version, {})
            model_path = model_info.get('path')
            
            if not model_path or not os.path.exists(model_path):
                # Try to construct the path if not in metadata
                model_path = os.path.join(self.config['storage_path'], f'v{version}', 'model.bin')
                if not os.path.exists(model_path):
                    self.logger.warning(f"Model path not found for version {version}")
                    continue
                
            try:
                # Remove the model file
                if os.path.isfile(model_path):
                    os.remove(model_path)
                elif os.path.isdir(model_path):
                    shutil.rmtree(model_path)
                
                # Remove the version directory if it exists and is empty
                version_dir = os.path.dirname(model_path)
                if os.path.exists(version_dir):
                    if not os.listdir(version_dir):  # Only remove if empty
                        os.rmdir(version_dir)
                
                # Remove from metadata if it exists
                if version in self.metadata:
                    del self.metadata[version]
                removed += 1
                self.logger.info(f"Removed old version: {version}")
                
            except Exception as e:
                self.logger.error(f"Failed to remove version {version}: {e}")
        
        # Save updated metadata if anything was removed
        if removed > 0:
            self._save_metadata()
            
        return removed
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """
        Get system resource metrics.
        
        Returns:
            Dict with system metrics (CPU, memory, disk usage, etc.)
        """
        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.5)
            
            # Get memory usage
            mem = psutil.virtual_memory()
            
            # Get disk usage for storage path
            disk = psutil.disk_usage(self.config['storage_path'])
            
            return {
                'cpu': {
                    'percent': cpu_percent,
                    'cores': psutil.cpu_count(),
                },
                'memory': {
                    'total': mem.total,
                    'available': mem.available,
                    'percent': mem.percent,
                    'used': mem.used,
                    'free': mem.free
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.percent
                },
                'network': {
                    'connections': len(psutil.net_connections())
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get system metrics: {e}")
            return {}
    
    def _get_latest_version(self) -> int:
        """Get the latest model version number."""
        versions = [0]
        if os.path.exists(self.config['storage_path']):
            for entry in os.listdir(self.config['storage_path']):
                if entry.startswith('v') and os.path.isdir(os.path.join(self.config['storage_path'], entry)):
                    try:
                        version = int(entry[1:])
                        versions.append(version)
                    except ValueError:
                        continue
        return max(versions)
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Load model metadata from disk."""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load metadata: {e}")
        return {}
    
    def _save_metadata(self) -> None:
        """Save model metadata to disk."""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save metadata: {e}")
    
    def _update_metadata(self, name: str, version: str, path: str, source: str) -> None:
        """Update metadata for a model version."""
        self.metadata[version] = {
            'name': name,
            'version': version,
            'path': path,
            'source': source,
            'downloaded_at': datetime.utcnow().isoformat(),
            'size': os.path.getsize(path),
            'checksum': self._calculate_checksum(path)
        }
        self._save_metadata()
    
    def _set_current_model(self, version: str, model_path: str) -> bool:
        """
        Set the current active model version.
        
        Args:
            version: Version string to set as current
            model_path: Path to the model file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Remove existing model/link if it exists
            if os.path.lexists(self.model_path):
                try:
                    if os.path.islink(self.model_path) or os.path.isfile(self.model_path):
                        os.remove(self.model_path)
                    elif os.path.isdir(self.model_path):
                        shutil.rmtree(self.model_path)
                except Exception as e:
                    self.logger.warning(f"Failed to remove existing model: {e}")
            
            # First try to create a symlink (faster, more efficient)
            try:
                os.symlink(model_path, self.model_path)
                self.logger.debug(f"Created symlink from {model_path} to {self.model_path}")
            except (OSError, AttributeError) as e:
                # Fall back to copying the file if symlink fails (e.g., on Windows without admin)
                self.logger.warning(f"Symlink creation failed, falling back to file copy: {e}")
                shutil.copy2(model_path, self.model_path)
            
            # Update current version in metadata
            self.metadata['current_version'] = version
            self._save_metadata()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to set current model: {e}")
            return False
    
    def _verify_model_integrity(self, model_path: str, version: str) -> bool:
        """Verify model integrity by checking checksum and metadata"""
        try:
            # Check if model file exists
            if not os.path.exists(model_path):
                return False
                
            # Load metadata
            metadata_path = os.path.join(self.config['storage_path'], f'{version}_metadata.json')
            if not os.path.exists(metadata_path):
                return False
                
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                
            # Verify version
            if metadata.get('version') != version:
                return False
                
            # Verify file size
            if os.path.getsize(model_path) != metadata.get('size', 0):
                return False
                
            # Verify checksum
            expected_checksum = metadata.get('checksum')
            if expected_checksum:
                return self._verify_checksum(model_path, expected_checksum)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error verifying model integrity: {e}")
            return False

    def _get_current_version(self) -> Optional[str]:
        """Get the current model version."""
        return self.metadata.get('current_version')
    
    def get_current_version(self) -> Optional[str]:
        """Get the current model version (public method)."""
        return self._get_current_version()
    
    @property
    def model_dir(self) -> str:
        """Get the model directory path."""
        return self.config['storage_path']
    
    @staticmethod
    def _verify_checksum(file_path: str, expected_checksum: str) -> bool:
        """Verify file checksum."""
        actual_checksum = ModelManager._calculate_checksum(file_path)
        return actual_checksum == expected_checksum.lower()
    
    @staticmethod
    def _calculate_checksum(file_path: str) -> str:
        """Calculate SHA-256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def _log_download_progress(downloaded: int, total: int) -> None:
        """Log download progress."""
        if total > 0:
            progress = (downloaded / total) * 100
            print(f"Download progress: {progress:.1f}% ({downloaded}/{total} bytes)", end='\r')
            if downloaded >= total:
                print()  # New line when download is complete

# Create an alias for backward compatibility
ModelManager = ModelManagerImpl
