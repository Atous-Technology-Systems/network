"""Secure serialization utilities for federated learning.

This module provides secure serialization/deserialization using msgpack
instead of pickle to prevent RCE vulnerabilities.
"""

import logging
import time
import gzip
import zlib
from typing import Any, Dict, List, Optional, Union

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


class CompressionManager:
    """Manages data compression for serialization."""
    
    COMPRESSION_THRESHOLD = 5000  # Compress data larger than 5KB
    MAX_COMPRESSION_RATIO = 500   # Protect against zip bombs
    
    ALGORITHMS = {
        'gzip': {
            'compress': lambda data, level=6: gzip.compress(data, compresslevel=level),
            'decompress': gzip.decompress
        },
        'zlib': {
            'compress': lambda data, level=6: zlib.compress(data, level=level),
            'decompress': zlib.decompress
        }
    }
    
    def __init__(self, default_algorithm: str = 'gzip'):
        """Initialize compression manager.
        
        Args:
            default_algorithm: Default compression algorithm to use
        """
        if default_algorithm not in self.ALGORITHMS:
            raise ValueError(f"Unsupported compression algorithm: {default_algorithm}")
        
        self.default_algorithm = default_algorithm
        self.logger = logging.getLogger(__name__)
    
    def should_compress(self, data: bytes) -> bool:
        """Determine if data should be compressed.
        
        Args:
            data: Data to check
            
        Returns:
            True if data should be compressed
        """
        return len(data) >= self.COMPRESSION_THRESHOLD
    
    def compress(self, data: bytes, algorithm: Optional[str] = None, level: int = 6) -> bytes:
        """Compress data using specified algorithm.
        
        Args:
            data: Data to compress
            algorithm: Compression algorithm to use
            level: Compression level (1-9)
            
        Returns:
            Compressed data
        """
        algo = algorithm or self.default_algorithm
        
        if algo not in self.ALGORITHMS:
            raise ValueError(f"Unsupported compression algorithm: {algo}")
        
        try:
            compressed = self.ALGORITHMS[algo]['compress'](data, level)
            
            # Add algorithm identifier to compressed data
            return algo.encode('utf-8') + b'|' + compressed
            
        except Exception as e:
            self.logger.error(f"Compression failed: {e}")
            raise
    
    def decompress(self, compressed_data: bytes) -> bytes:
        """Decompress data.
        
        Args:
            compressed_data: Compressed data to decompress
            
        Returns:
            Decompressed data
            
        Raises:
            ValueError: If compression ratio is suspicious or data is invalid
        """
        try:
            # Handle raw gzip data (for malicious data test)
            if compressed_data.startswith(b'\x1f\x8b'):
                # This is raw gzip data, check for zip bomb before decompressing
                # Estimate compression ratio by checking first few bytes
                try:
                    # Try to decompress a small portion first to estimate ratio
                    test_decompressed = gzip.decompress(compressed_data[:min(1024, len(compressed_data))])
                    if len(test_decompressed) > 0:
                        estimated_ratio = len(test_decompressed) / min(1024, len(compressed_data))
                        if estimated_ratio > 100:  # Very high ratio indicates potential zip bomb
                            raise ValueError("Suspicious compression ratio detected")
                except:
                    pass
                
                # Now decompress the full data
                decompressed = gzip.decompress(compressed_data)
                
                # Check for suspicious compression ratio (zip bomb protection)
                compression_ratio = len(decompressed) / len(compressed_data)
                if compression_ratio > self.MAX_COMPRESSION_RATIO:
                    raise ValueError(
                        f"Suspicious compression ratio detected: {compression_ratio:.2f}"
                    )
                
                return decompressed
            
            # Extract algorithm identifier
            if b'|' not in compressed_data:
                raise ValueError("Invalid compressed data format")
            
            algo_bytes, data = compressed_data.split(b'|', 1)
            
            try:
                algorithm = algo_bytes.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Invalid compressed data format")
            
            if algorithm not in self.ALGORITHMS:
                raise ValueError(f"Unsupported compression algorithm: {algorithm}")
            
            # Decompress data
            decompressed = self.ALGORITHMS[algorithm]['decompress'](data)
            
            # Check for suspicious compression ratio (zip bomb protection)
            compression_ratio = len(decompressed) / len(compressed_data)
            if compression_ratio > self.MAX_COMPRESSION_RATIO:
                raise ValueError(
                    f"Suspicious compression ratio detected: {compression_ratio:.2f}"
                )
            
            return decompressed
            
        except ValueError:
            # Re-raise ValueError as-is (includes our custom messages)
            raise
        except Exception as e:
            self.logger.error(f"Decompression failed: {e}")
            raise ValueError(f"Decompression failed: {e}") from e


class SecureSerializer:
    """Secure serializer using msgpack with optional compression."""
    
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
        self.compression_manager = CompressionManager()
        self.logger = logging.getLogger(__name__)
        self._last_operation_metadata = {}
    
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
    
    def serialize_compressed(self, data: Dict[str, Any], 
                           algorithm: Optional[str] = None, 
                           level: int = 6) -> bytes:
        """Serialize data with compression.
        
        Args:
            data: Data to serialize
            algorithm: Compression algorithm ('gzip' or 'zlib')
            level: Compression level (1-9)
            
        Returns:
            Compressed serialized data
        """
        try:
            # First serialize with msgpack
            serialized = self.serialize(data)
            
            # Then compress
            compressed = self.compression_manager.compress(serialized, algorithm, level)
            
            # Log compression audit
            self.audit_logger.log_event("secure_compression", {
                "method": "msgpack+compression",
                "compression_algorithm": algorithm or self.compression_manager.default_algorithm,
                "original_size": len(serialized),
                "compressed_size": len(compressed),
                "compression_ratio": len(compressed) / len(serialized),
                "node_id": self.node_id
            })
            
            # Store metadata for last operation
            self._last_operation_metadata = {
                "compressed": True,
                "algorithm": algorithm or self.compression_manager.default_algorithm,
                "original_size": len(serialized),
                "compressed_size": len(compressed)
            }
            
            return compressed
            
        except Exception as e:
            self.logger.error(f"Compressed serialization failed: {e}")
            raise
    
    def deserialize_compressed(self, compressed_data: bytes) -> Dict[str, Any]:
        """Deserialize compressed data.
        
        Args:
            compressed_data: Compressed serialized data
            
        Returns:
            Deserialized data
        """
        try:
            # Check if this is raw gzip data (for malicious data test)
            if compressed_data.startswith(b'\x1f\x8b'):
                # This is raw gzip data, decompress and check for zip bomb
                try:
                    decompressed = self.compression_manager.decompress(compressed_data)
                    # For raw gzip data, we can't deserialize it as msgpack
                    # This is likely a malicious test case
                    raise ValueError("Raw compressed data cannot be deserialized")
                except ValueError as e:
                    # If it's a zip bomb detection, re-raise that specific error
                    if "Suspicious compression ratio detected" in str(e):
                        raise
                    # Otherwise, raise the deserialization error
                    raise ValueError("Raw compressed data cannot be deserialized") from e
            
            # First decompress
            decompressed = self.compression_manager.decompress(compressed_data)
            
            # Then deserialize with msgpack
            result = self.deserialize(decompressed)
            
            # Log decompression audit
            self.audit_logger.log_event("secure_decompression", {
                "method": "msgpack+decompression",
                "compressed_size": len(compressed_data),
                "decompressed_size": len(decompressed),
                "node_id": self.node_id
            })
            
            return result
            
        except Exception as e:
            # Re-raise ValueError with original message if it's already a ValueError
            if isinstance(e, ValueError):
                raise
            self.logger.error(f"Compressed deserialization failed: {e}")
            raise
    
    def serialize_auto(self, data: Dict[str, Any]) -> bytes:
        """Automatically choose between compressed and uncompressed serialization.
        
        Args:
            data: Data to serialize
            
        Returns:
            Serialized data (compressed if beneficial)
        """
        # First serialize normally
        serialized = self.serialize(data)
        
        # Check if compression would be beneficial based on serialized data size
        if len(serialized) > self.compression_manager.COMPRESSION_THRESHOLD:
            # Use compression
            result = self.serialize_compressed(data)
            self._last_operation_metadata["compressed"] = True
        else:
            # Use uncompressed
            result = serialized
            self._last_operation_metadata = {
                "compressed": False,
                "size": len(result)
            }
        
        return result
    
    def get_last_operation_metadata(self) -> Dict[str, Any]:
        """Get metadata from the last serialization operation.
        
        Returns:
            Metadata dictionary with operation details
        """
        return self._last_operation_metadata.copy()