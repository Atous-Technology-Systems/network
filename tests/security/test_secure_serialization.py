#!/usr/bin/env python3
"""
Security Tests for Secure Serialization - TASK-001

This module tests the replacement of insecure pickle serialization
with secure msgpack serialization to prevent RCE vulnerabilities.

TDD Phase: RED - Failing tests that define security requirements
"""

import pytest
import msgpack
import json
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List
import numpy as np

# Import the module under test
try:
    from atous_sec_network.core.secure_fl import SecureFederatedLearning
except ImportError:
    pytest.skip("SecureFederatedLearning not available", allow_module_level=True)


class TestSecureSerialization:
    """Test secure serialization implementation - TASK-001"""
    
    def setup_method(self):
        """Setup test environment"""
        self.secure_fl = SecureFederatedLearning(node_id="test_node")
        
        # Test data that should be serializable
        self.safe_test_data = {
            "model_weights": [1.0, 2.0, 3.0],
            "metadata": {
                "version": "1.0",
                "timestamp": 1234567890,
                "node_id": "test_node"
            },
            "gradients": [[0.1, 0.2], [0.3, 0.4]]
        }
        
        # Malicious data that should be rejected
        self.malicious_data = {
            "__reduce__": (eval, ("__import__('os').system('echo pwned')",)),
            "dangerous": "exec('print(\"hacked\")')"
        }
    
    def test_msgpack_serialization_replaces_pickle(self):
        """Test that msgpack is used instead of pickle for serialization"""
        # Test the secure serialization method directly
        
        with patch('atous_sec_network.core.serialization.msgpack') as mock_msgpack:
            mock_msgpack.packb.return_value = b"serialized_data"
            
            # This should use msgpack, not pickle
            try:
                serialized_data = self.secure_fl._secure_serialize(self.safe_test_data)
                
                # Verify msgpack was called, not pickle
                mock_msgpack.packb.assert_called_once_with(self.safe_test_data, use_bin_type=True)
                assert serialized_data == b"serialized_data"
                
            except Exception as e:
                pytest.fail(f"Serialization should use msgpack, not pickle: {e}")
    
    def test_msgpack_deserialization_replaces_pickle(self):
        """Test that msgpack is used instead of pickle for deserialization"""
        # Test the secure deserialization method directly
        
        mock_serialized_data = b"mock_serialized_data"
        
        with patch('atous_sec_network.core.serialization.msgpack') as mock_msgpack:
            mock_msgpack.unpackb.return_value = self.safe_test_data
            
            try:
                deserialized_data = self.secure_fl._secure_deserialize(mock_serialized_data)
                
                # Verify msgpack was called for deserialization
                mock_msgpack.unpackb.assert_called_once_with(mock_serialized_data, raw=False, strict_map_key=False)
                assert deserialized_data == self.safe_test_data
                
            except Exception as e:
                pytest.fail(f"Deserialization should use msgpack, not pickle: {e}")
    
    def test_input_validation_prevents_malicious_data(self):
        """Test that input validation prevents malicious serialized data"""
        # Test that malicious data is rejected during serialization
        
        with pytest.raises(TypeError, match="Unsupported data type for serialization"):
            # This should raise an exception due to input validation
            self.secure_fl._secure_serialize(self.malicious_data)
    
    def test_schema_validation_enforces_data_structure(self):
        """Test that schema validation enforces expected data structure"""
        # Test schema validation with expected schema
        
        invalid_data = {
            "unexpected_field": "should_not_be_allowed",
            "missing_required_fields": True
        }
        
        expected_schema = {
            "model_weights": list,
            "metadata": dict
        }
        
        with pytest.raises(ValueError, match="Missing required field"):
            # This should raise an exception due to schema validation
            self.secure_fl._validate_data_schema(invalid_data, expected_schema)
    
    def test_serialization_performance_acceptable(self):
        """Test that msgpack serialization performance is acceptable"""
        # RED: This test should fail initially due to performance requirements
        
        import time
        
        # Large test data to measure performance
        large_data = {
            "weights": [float(i) for i in range(10000)],
            "metadata": {"large_field": "x" * 1000}
        }
        
        start_time = time.time()
        
        # Serialize with new method
        serialized = self.secure_fl._secure_serialize(large_data)
        
        end_time = time.time()
        serialization_time = end_time - start_time
        
        # Performance requirement: < 100ms for 10k elements
        assert serialization_time < 0.1, f"Serialization too slow: {serialization_time}s"
        assert len(serialized) > 0
    
    def test_deserialization_performance_acceptable(self):
        """Test that msgpack deserialization performance is acceptable"""
        # RED: This test should fail initially due to performance requirements
        
        import time
        
        # Prepare serialized data
        large_data = {
            "weights": [float(i) for i in range(10000)],
            "metadata": {"large_field": "x" * 1000}
        }
        
        serialized = msgpack.packb(large_data)
        
        start_time = time.time()
        
        # Deserialize with new method
        deserialized = self.secure_fl._secure_deserialize(serialized)
        
        end_time = time.time()
        deserialization_time = end_time - start_time
        
        # Performance requirement: < 100ms for 10k elements
        assert deserialization_time < 0.1, f"Deserialization too slow: {deserialization_time}s"
        assert deserialized == large_data
    
    def test_backward_compatibility_maintained(self):
        """Test that existing API contracts are maintained"""
        # Test that the secure serialization methods work correctly
        
        # Test that serialization/deserialization roundtrip works
        try:
            serialized = self.secure_fl._secure_serialize(self.safe_test_data)
            deserialized = self.secure_fl._secure_deserialize(serialized)
            
            # Data should be preserved
            assert deserialized == self.safe_test_data
            
        except Exception as e:
            pytest.fail(f"API compatibility broken: {e}")
    
    def test_no_pickle_imports_in_secure_methods(self):
        """Test that pickle is not imported in secure serialization methods"""
        # RED: This test should fail initially because pickle is still used
        
        import inspect
        import ast
        
        # Get source code of the secure_fl module
        source_file = inspect.getfile(SecureFederatedLearning)
        
        with open(source_file, 'r') as f:
            source_code = f.read()
        
        # Parse the AST to find import statements
        tree = ast.parse(source_code)
        
        pickle_imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if 'pickle' in alias.name:
                        pickle_imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module and 'pickle' in node.module:
                    pickle_imports.append(node.module)
        
        # Should have no pickle imports after refactoring
        assert len(pickle_imports) == 0, f"Found pickle imports: {pickle_imports}"
    
    def test_security_audit_log_created(self):
        """Test that security operations are logged for audit"""
        # Test that security audit log is created during operations
        
        # Perform serialization operation
        serialized = self.secure_fl._secure_serialize(self.safe_test_data)
        
        # Check that audit log was created
        audit_log = self.secure_fl.get_security_audit_log()
        
        assert len(audit_log) >= 0, "Security audit log should be accessible"
        
        # Check the log entry details
        log_entry = audit_log[0]
        assert log_entry["event_type"] == "secure_serialization"
        assert log_entry["details"]["method"] == "msgpack"
        assert log_entry["details"]["node_id"] == "test_node"
        assert "timestamp" in log_entry


class TestSecureSerializationEdgeCases:
    """Test edge cases and error conditions for secure serialization"""
    
    def setup_method(self):
        """Setup test environment"""
        self.secure_fl = SecureFederatedLearning(node_id="test_node")
    
    def test_empty_data_serialization(self):
        """Test serialization of empty data structures"""
        empty_data = {}
        
        try:
            serialized = self.secure_fl._secure_serialize(empty_data)
            deserialized = self.secure_fl._secure_deserialize(serialized)
            
            assert deserialized == empty_data
            
        except Exception as e:
            pytest.fail(f"Empty data serialization should work: {e}")
    
    def test_large_data_serialization(self):
        """Test serialization of large data structures"""
        # Create data larger than typical memory constraints
        large_data = {
            "huge_array": [i for i in range(100000)],
            "nested": {f"key_{i}": f"value_{i}" for i in range(1000)}
        }
        
        try:
            serialized = self.secure_fl._secure_serialize(large_data)
            deserialized = self.secure_fl._secure_deserialize(serialized)
            
            assert deserialized == large_data
            
        except Exception as e:
            pytest.fail(f"Large data serialization should work: {e}")
    
    def test_corrupted_data_handling(self):
        """Test handling of corrupted serialized data"""
        corrupted_data = b"corrupted_msgpack_data_that_cannot_be_parsed"
        
        with pytest.raises(ValueError, match="Corrupted or invalid serialized data"):
            self.secure_fl._secure_deserialize(corrupted_data)
    
    def test_unsupported_data_types(self):
        """Test handling of unsupported data types"""
        # Data with unsupported types (like functions)
        unsupported_data = {
            "function": lambda x: x + 1,
            "class": SecureFederatedLearning
        }
        
        with pytest.raises(TypeError, match="Unsupported data type for serialization"):
            self.secure_fl._secure_serialize(unsupported_data)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])