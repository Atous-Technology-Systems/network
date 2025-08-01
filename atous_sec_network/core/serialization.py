"""Secure serialization utilities for federated learning.

This module provides secure serialization/deserialization using msgpack
instead of pickle to prevent RCE vulnerabilities.
"""

import logging
import time
from typing import Any, Dict, List

try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


class SecurityAuditLogger:
    """Manages security audit logging."""
    
    MAX_LOG_ENTRIES = 1000
    
    def __init__(self):
        """Initialize audit logger."""
        self.audit_log: List[Dict[str, Any]] = []
        self.logger = logging.getLogger(__name__)
    
    def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log a security event.
        
        Args:
            event_type: Type of security event
            details: Event details
        """
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "details": details
        }
        
        self.audit_log.append(event)
        
        # Keep only last MAX_LOG_ENTRIES to prevent memory issues
        if len(self.audit_log) > self.MAX_LOG_ENTRIES:
            self.audit_log = self.audit_log[-self.MAX_LOG_ENTRIES:]
    
    def get_log(self) -> List[Dict[str, Any]]:
        """Get copy of audit log.
        
        Returns:
            Copy of audit log entries
        """
        return self.audit_log.copy()


class DataValidator:
    """Validates data for secure serialization."""
    
    SAFE_TYPES = (str, int, float, bool, type(None), list, dict, tuple)
    
    def validate_for_serialization(self, data: Any, path: str = "root") -> None:
        """Validate data before serialization to prevent dangerous objects.
        
        Args:
            data: Data to validate
            path: Current path in data structure (for error reporting)
            
        Raises:
            TypeError: If data contains unsupported or dangerous types
        """
        # Check for dangerous attributes
        if hasattr(data, '__reduce__') and callable(getattr(data, '__reduce__')):
            if not isinstance(data, self.SAFE_TYPES):
                raise TypeError(
                    f"Unsupported data type for serialization at {path}: {type(data)}"
                )
        
        if isinstance(data, dict):
            self._validate_dict(data, path)
        elif isinstance(data, (list, tuple)):
            self._validate_sequence(data, path)
        elif not isinstance(data, self.SAFE_TYPES):
            # Allow numpy arrays if available
            if HAS_NUMPY and isinstance(data, np.ndarray):
                return  # numpy arrays are safe
            
            raise TypeError(
                f"Unsupported data type for serialization at {path}: {type(data)}"
            )
    
    def _validate_dict(self, data: dict, path: str) -> None:
        """Validate dictionary data."""
        for key, value in data.items():
            if not isinstance(key, (str, int, float)):
                raise TypeError(
                    f"Unsupported key type at {path}.{key}: {type(key)}"
                )
            self.validate_for_serialization(value, f"{path}.{key}")
    
    def _validate_sequence(self, data: (list, tuple), path: str) -> None:
        """Validate list or tuple data."""
        for i, item in enumerate(data):
            self.validate_for_serialization(item, f"{path}[{i}]")
    
    def validate_deserialized_data(self, data: Any) -> None:
        """Validate deserialized data for security.
        
        Args:
            data: Deserialized data to validate
            
        Raises:
            ValueError: If data has unsafe type
        """
        if not isinstance(data, self.SAFE_TYPES):
            raise ValueError(f"Deserialized data has unsafe type: {type(data)}")
    
    def validate_schema(self, data: Dict[str, Any], 
                       expected_schema: Dict[str, type]) -> None:
        """Validate data against expected schema.
        
        Args:
            data: Data to validate
            expected_schema: Expected schema with field names and types
            
        Raises:
            ValueError: If data doesn't match schema
        """
        if not isinstance(data, dict):
            raise ValueError(f"Expected dict, got {type(data)}")
        
        for field, expected_type in expected_schema.items():
            if field not in data:
                raise ValueError(f"Missing required field: {field}")
            
            if not isinstance(data[field], expected_type):
                raise ValueError(
                    f"Field {field} has wrong type. "
                    f"Expected {expected_type}, got {type(data[field])}"
                )


class SecureSerializer:
    """Secure serializer using msgpack."""
    
    def __init__(self, node_id: str = "default_node"):
        """Initialize secure serializer.
        
        Args:
            node_id: Node identifier for audit logging
        """
        if not HAS_MSGPACK:
            raise RuntimeError(
                "msgpack is required for secure serialization. "
                "Install with: pip install msgpack"
            )
        
        self.node_id = node_id
        self.validator = DataValidator()
        self.audit_logger = SecurityAuditLogger()
        self.logger = logging.getLogger(__name__)
    
    def serialize(self, data: Dict[str, Any]) -> bytes:
        """Securely serialize data using msgpack.
        
        Args:
            data: Data to serialize
            
        Returns:
            Serialized data as bytes
            
        Raises:
            TypeError: If data contains unsupported types
        """
        try:
            # Validate data before serialization
            self.validator.validate_for_serialization(data)
            
            # Use msgpack for secure serialization
            serialized = msgpack.packb(data, use_bin_type=True)
            
            # Log security audit
            self.audit_logger.log_event("secure_serialization", {
                "method": "msgpack",
                "data_size": len(serialized),
                "node_id": self.node_id
            })
            
            return serialized
            
        except Exception as e:
            self.logger.error(f"Secure serialization failed: {e}")
            raise
    
    def deserialize(self, data: bytes) -> Dict[str, Any]:
        """Securely deserialize data using msgpack.
        
        Args:
            data: Serialized data to deserialize
            
        Returns:
            Deserialized data
            
        Raises:
            ValueError: If data is corrupted or invalid
        """
        try:
            # Use msgpack for secure deserialization
            deserialized = msgpack.unpackb(
                data, raw=False, strict_map_key=False
            )
            
            # Validate deserialized data
            self.validator.validate_deserialized_data(deserialized)
            
            # Log security audit
            self.audit_logger.log_event("secure_deserialization", {
                "method": "msgpack",
                "data_size": len(data),
                "node_id": self.node_id
            })
            
            return deserialized
            
        except Exception as e:
            # Provide more specific error messages for corrupted data
            if "unpack" in str(e) or "decode" in str(e):
                raise ValueError("Corrupted or invalid serialized data") from e
            self.logger.error(f"Secure deserialization failed: {e}")
            raise
    
    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get security audit log.
        
        Returns:
            List of security events
        """
        return self.audit_logger.get_log()
    
    def validate_schema(self, data: Dict[str, Any], 
                       expected_schema: Dict[str, type]) -> None:
        """Validate data against expected schema.
        
        Args:
            data: Data to validate
            expected_schema: Expected schema
        """
        self.validator.validate_schema(data, expected_schema)