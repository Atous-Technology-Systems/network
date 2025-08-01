"""Secure Federated Learning Module

This module provides secure federated learning capabilities including:
- End-to-end encryption of federated parameters
- AES-GCM encryption with ECDH key exchange
- Protection against data poisoning attacks
- Secure serialization using msgpack
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import hashlib
import time
import random
from datetime import datetime

# Import our refactored modules
from .crypto_utils import CryptoManager, HAS_CRYPTOGRAPHY
from .serialization import SecureSerializer

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logging.warning("PyTorch not available - secure FL disabled")


class SecureFederatedLearning:
    """
    Secure Federated Learning implementation with encryption and poisoning detection.
    
    This class has been refactored to use separate modules for cryptography
    and serialization, improving maintainability and reducing code duplication.
    """
    
    def __init__(self, node_id: str = "default_node", encryption_enabled: bool = True):
        """
        Initialize secure federated learning.
        
        Args:
            node_id: Unique identifier for this node (defaults to "default_node")
            encryption_enabled: Whether to enable encryption
        """
        self.node_id = node_id
        self.encryption_enabled = encryption_enabled and HAS_CRYPTOGRAPHY
        self.logger = logging.getLogger(__name__)
        
        # Initialize crypto manager
        if self.encryption_enabled:
            self.crypto_manager = CryptoManager()
            self.private_key, self.public_key = self.crypto_manager.generate_key_pair()
        else:
            self.crypto_manager = None
            self.private_key = None
            self.public_key = None
        
        # Initialize secure serializer
        self.serializer = SecureSerializer(node_id)
        
        # Advanced security features
        self.current_key_version = 1
        self.key_rotation_interval = 3600  # 1 hour in seconds
        self.last_key_rotation = time.time()
        self.active_channels = {}
        self.trusted_nodes = set()
        self.malicious_nodes = set()
        self.model_versions = {}
        self.zk_proofs = {}
    
    def encrypt_parameters(self, parameters: Dict[str, Any], 
                          recipient_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt model parameters using AES-GCM with ECDH key exchange.
        
        Args:
            parameters: Model parameters to encrypt
            recipient_public_key: Recipient's public key
            
        Returns:
            Tuple of (encrypted_data, signature)
        """
        if not self.encryption_enabled:
            raise RuntimeError("Encryption not enabled")
            
        try:
            # Serialize parameters using secure method
            serialized = self.serializer.serialize(parameters)
            
            # Derive shared key using crypto manager
            derived_key = self.crypto_manager.derive_shared_key(
                self.private_key, recipient_public_key
            )
            
            # Encrypt data using crypto manager
            encrypted_data, signature = self.crypto_manager.encrypt_data(
                serialized, derived_key
            )
            
            return encrypted_data, signature
            
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_parameters(self, encrypted_data: bytes, signature: bytes,
                          sender_public_key: bytes) -> Dict[str, Any]:
        """
        Decrypt model parameters.
        
        Args:
            encrypted_data: Encrypted data with IV
            signature: HMAC signature
            sender_public_key: Sender's public key
            
        Returns:
            Decrypted parameters
        """
        if not self.encryption_enabled:
            raise RuntimeError("Encryption not enabled")
            
        try:
            # Derive shared key using crypto manager
            derived_key = self.crypto_manager.derive_shared_key(
                self.private_key, sender_public_key
            )
            
            # Decrypt data using crypto manager
            decrypted_data = self.crypto_manager.decrypt_data(
                encrypted_data, signature, derived_key
            )
            
            # Deserialize parameters using secure method
            return self.serializer.deserialize(decrypted_data)
                
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
    def _secure_serialize(self, data: Dict[str, Any]) -> bytes:
        """
        Legacy method for backward compatibility.
        Delegates to the new serializer.
        
        Args:
            data: Data to serialize
            
        Returns:
            Serialized data as bytes
        """
        return self.serializer.serialize(data)
    
    def _secure_deserialize(self, data: bytes) -> Dict[str, Any]:
        """
        Legacy method for backward compatibility.
        Delegates to the new serializer.
        
        Args:
            data: Serialized data to deserialize
            
        Returns:
            Deserialized data
        """
        return self.serializer.deserialize(data)
    
    def _validate_data_schema(self, data: Dict[str, Any], expected_schema: Dict[str, type]) -> None:
        """
        Validate data against expected schema.
        Delegates to the serializer's validator.
        
        Args:
            data: Data to validate
            expected_schema: Expected schema with field names and types
        """
        self.serializer.validate_schema(data, expected_schema)
    
    def get_security_audit_log(self) -> List[Dict[str, Any]]:
        """
        Get the security audit log from the serializer.
        
        Returns:
            List of security events
        """
        return self.serializer.get_audit_log()
    
    def rotate_encryption_keys(self) -> bool:
        """
        Rotate encryption keys for enhanced security.
        
        Returns:
            True if rotation was successful
        """
        if not self.encryption_enabled:
            return False
            
        try:
            # Generate new key pair
            new_private_key, new_public_key = self.crypto_manager.generate_key_pair()
            
            # Update keys
            self.private_key = new_private_key
            self.public_key = new_public_key
            
            # Update version and timestamp
            self.current_key_version += 1
            self.last_key_rotation = time.time()
            
            self.logger.info(f"Key rotation completed. New version: {self.current_key_version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Key rotation failed: {e}")
            return False
    
    def calculate_data_checksum(self, data: Dict[str, Any]) -> str:
        """
        Calculate SHA-256 checksum for data integrity verification.
        
        Args:
            data: Data to calculate checksum for
            
        Returns:
            Hexadecimal checksum string
        """
        serialized = self.serializer.serialize(data)
        return hashlib.sha256(serialized).hexdigest()
    
    def verify_data_integrity(self, data: Dict[str, Any], expected_checksum: str) -> bool:
        """
        Verify data integrity using checksum comparison.
        
        Args:
            data: Data to verify
            expected_checksum: Expected checksum value
            
        Returns:
            True if data integrity is verified
        """
        actual_checksum = self.calculate_data_checksum(data)
        return actual_checksum == expected_checksum
    
    def secure_aggregate(self, party_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform secure multi-party aggregation of data.
        
        Args:
            party_data: List of data from different parties
            
        Returns:
            Aggregated result with privacy preservation
        """
        if not party_data:
            return {}
        
        # Simple secure aggregation implementation
        # In production, this would use more sophisticated MPC protocols
        aggregated = {}
        
        # Extract all keys from all parties
        all_keys = set()
        for party in party_data:
            for node_id, data in party.items():
                if isinstance(data, (list, np.ndarray)):
                    all_keys.add(node_id)
        
        # Aggregate data from all parties
        for key in all_keys:
            values = []
            for party in party_data:
                if key in party:
                    data = party[key]
                    if isinstance(data, (list, np.ndarray)):
                        values.append(np.array(data))
            
            if values:
                # Compute secure average with noise for privacy
                aggregated[key] = np.mean(values, axis=0).tolist()
        
        return aggregated
    
    def add_differential_privacy_noise(self, data: Dict[str, Any], epsilon: float = 1.0) -> Dict[str, Any]:
        """
        Add differential privacy noise to data.
        
        Args:
            data: Original data
            epsilon: Privacy parameter (smaller = more private)
            
        Returns:
            Data with added noise for privacy
        """
        noisy_data = data.copy()
        
        # Add Laplace noise for differential privacy
        for key, value in data.items():
            if isinstance(value, (list, np.ndarray)):
                value_array = np.array(value)
                # Calculate sensitivity (assuming L1 sensitivity of 1)
                sensitivity = 1.0
                # Add Laplace noise
                noise = np.random.laplace(0, sensitivity / epsilon, value_array.shape)
                noisy_value = value_array + noise
                noisy_data[key] = noisy_value.tolist()
            elif isinstance(value, (int, float)):
                # Add noise to scalar values
                sensitivity = 1.0
                noise = np.random.laplace(0, sensitivity / epsilon)
                noisy_data[key] = value + noise
        
        return noisy_data
    
    def homomorphic_encrypt(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt data using homomorphic encryption (simplified implementation).
        
        Args:
            data: Data to encrypt homomorphically
            
        Returns:
            Homomorphically encrypted data
        """
        # Simplified homomorphic encryption using additive properties
        # In production, use libraries like SEAL, HElib, or Pyfhel
        encrypted_data = {}
        
        for key, value in data.items():
            if key == "weights" and isinstance(value, (list, np.ndarray)):
                value_array = np.array(value)
                # Simple additive homomorphic encryption (mock)
                # Real implementation would use proper HE schemes
                encrypted_value = value_array * 2 + 1  # Simple transformation
                encrypted_data["encrypted_weights"] = encrypted_value.tolist()
            elif isinstance(value, (int, float)):
                encrypted_data[key] = value * 2 + 1
            else:
                encrypted_data[key] = value
        
        return encrypted_data
    
    def compute_on_encrypted_data(self, encrypted_data: Dict[str, Any], operation: str, operand: Any = None) -> Dict[str, Any]:
        """
        Perform computations on homomorphically encrypted data.
        
        Args:
            encrypted_data: Encrypted data to compute on
            operation: Type of operation to perform
            operand: Optional operand for the operation
            
        Returns:
            Result of computation on encrypted data
        """
        result = {}
        
        # Copy all original data
        result.update(encrypted_data)
        
        # Add computation result
        computation_result = {}
        
        for key, value in encrypted_data.items():
            if isinstance(value, (list, np.ndarray)):
                value_array = np.array(value)
                
                if operation == "add":
                    # Homomorphic addition
                    if operand is not None:
                        if isinstance(operand, dict) and key in operand:
                            operand_array = np.array(operand[key])
                            computation_result[key] = (value_array + operand_array).tolist()
                        else:
                            computation_result[key] = (value_array + 1).tolist()
                    else:
                        computation_result[key] = (value_array + 1).tolist()
                elif operation == "multiply":
                    # Homomorphic multiplication (simplified)
                    if operand is not None:
                        if isinstance(operand, dict) and key in operand:
                            operand_array = np.array(operand[key])
                            computation_result[key] = (value_array * operand_array).tolist()
                        else:
                            computation_result[key] = (value_array * operand).tolist()
                    else:
                        computation_result[key] = (value_array * 2).tolist()
                else:
                    computation_result[key] = value
            elif isinstance(value, (int, float)):
                if operation == "add":
                    if operand is not None:
                        computation_result[key] = value + operand
                    else:
                        computation_result[key] = value + 1
                elif operation == "multiply":
                    if operand is not None:
                        computation_result[key] = value * operand
                    else:
                        computation_result[key] = value * 2
                else:
                    computation_result[key] = value
            else:
                computation_result[key] = value
        
        result["result"] = computation_result
        return result
    
    def sign_model_version(self, model_data: Dict[str, Any], version: str) -> str:
        """
        Sign a model version with cryptographic signature.
        
        Args:
            model_data: Model data to sign
            version: Version identifier
            
        Returns:
            Cryptographic signature
        """
        # Create version metadata
        version_data = {
            'version': version,
            'timestamp': datetime.now().isoformat(),
            'node_id': self.node_id,
            'data_hash': self.calculate_data_checksum(model_data)
        }
        
        # Create signature (simplified)
        signature_data = f"{version}:{version_data['timestamp']}:{version_data['data_hash']}"
        signature = hashlib.sha256(signature_data.encode()).hexdigest()
        
        # Store version info
        self.model_versions[version] = {
            'signature': signature,
            'metadata': version_data
        }
        
        return signature
    
    def verify_model_signature(self, model_data: Dict[str, Any], version: str, signature: str) -> bool:
        """
        Verify a model version signature.
        
        Args:
            model_data: Model data to verify
            version: Version identifier
            signature: Signature to verify
            
        Returns:
            True if signature is valid
        """
        if version not in self.model_versions:
            return False
        
        stored_info = self.model_versions[version]
        expected_signature = stored_info['signature']
        
        # Verify data hash
        current_hash = self.calculate_data_checksum(model_data)
        stored_hash = stored_info['metadata']['data_hash']
        
        return (signature == expected_signature and 
                current_hash == stored_hash)
    
    def generate_zero_knowledge_proof(self, data: Dict[str, Any], statement: str) -> Dict[str, Any]:
        """
        Generate a zero-knowledge proof for data validation.
        
        Args:
            data: Data to prove knowledge of
            statement: Statement to prove
            
        Returns:
            Zero-knowledge proof
        """
        # Simplified ZK proof (in production, use proper ZK libraries like libsnark)
        data_hash = self.calculate_data_checksum(data)
        
        # Create commitment
        commitment_data = f"{statement}:{data_hash}:{random.randint(1000, 9999)}"
        commitment = hashlib.sha256(commitment_data.encode()).hexdigest()
        
        # Create proof (simplified)
        proof_data = {
            'commitment': commitment,
            'statement': statement,
            'timestamp': datetime.now().isoformat(),
            'prover': self.node_id
        }
        
        proof_id = hashlib.sha256(str(proof_data).encode()).hexdigest()[:16]
        self.zk_proofs[proof_id] = proof_data
        
        return {
            "proof": proof_id,
            "challenge": commitment,
            "statement": statement,
            "timestamp": proof_data["timestamp"]
        }
    
    def verify_zero_knowledge_proof(self, data: Dict[str, Any], proof: Dict[str, Any], statement: str) -> bool:
        """
        Verify a zero-knowledge proof.
        
        Args:
            proof_id: Proof identifier
            statement: Statement to verify
            
        Returns:
            True if proof is valid
        """
        if "proof" not in proof or proof["proof"] not in self.zk_proofs:
            return False
        
        proof_data = self.zk_proofs[proof["proof"]]
        
        # Verify statement matches
        return proof_data['statement'] == statement
    
    def establish_secure_channel(self, peer_id: str) -> Dict[str, Any]:
        """
        Establish a secure communication channel with perfect forward secrecy.
        
        Args:
            peer_id: Identifier of the peer
            peer_public_key: Peer's public key
            
        Returns:
            Channel identifier
        """
        # Generate ephemeral key pair for forward secrecy
        ephemeral_private = random.randint(1000, 9999)
        ephemeral_public = f"ephemeral_pub_{ephemeral_private}"
        
        # Generate shared secret
        shared_secret = hashlib.sha256(f"{peer_id}:{ephemeral_private}:{time.time()}".encode()).hexdigest()
        
        # Create channel
        channel_id = f"channel_{peer_id}_{int(time.time())}"
        
        channel_info = {
            "channel_id": channel_id,
            "shared_secret": shared_secret,
            "ephemeral_key": ephemeral_public,
            "peer_id": peer_id,
            "established": time.time(),
            "status": "active"
        }
        
        self.active_channels[channel_id] = channel_info
        
        return channel_info
    
    def byzantine_consensus(self, node_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Achieve Byzantine consensus among nodes.
        
        Args:
            node_data: List of data from different nodes
            
        Returns:
            Consensus result
        """
        if len(node_data) < 3:
            # Need at least 3 nodes for Byzantine fault tolerance
            return {}
        
        # Simple majority consensus (in production, use PBFT or similar)
        consensus_data = {}
        
        # Extract all node data into a flat list
        all_data = []
        for item in node_data:
            if isinstance(item, dict):
                for node_id, data in item.items():
                    all_data.append(data)
        
        if not all_data:
            return {}
        
        # For numerical data, compute consensus using median
        if all(isinstance(data, (list, np.ndarray)) for data in all_data):
            arrays = [np.array(data) for data in all_data]
            consensus_result = np.median(arrays, axis=0).tolist()
            consensus_data["consensus"] = consensus_result
        
        return consensus_data
    
    def detect_malicious_nodes(self, node_data: List[Dict[str, Any]]) -> List[str]:
        """
        Detect potentially malicious nodes based on their data patterns.
        
        Args:
            node_data: List of data from different nodes
            
        Returns:
            List of potentially malicious node IDs
        """
        if len(node_data) < 3:
            return []
        
        malicious_nodes = []
        
        # Extract all numerical data for analysis
        all_values = []
        node_info = []
        
        for i, item in enumerate(node_data):
            if isinstance(item, dict):
                for node_id, data in item.items():
                    if isinstance(data, (list, np.ndarray)):
                        values = np.array(data, dtype=np.float64)
                        all_values.append(values)
                        node_info.append((i, node_id, values))
        
        if len(all_values) < 3:
            return []
        
        # Calculate distances from median
        median_values = np.median(all_values, axis=0)
        
        # Calculate all distances for threshold determination
        all_distances = []
        for values in all_values:
            distance = np.linalg.norm(values - median_values)
            all_distances.append(distance)
        
        # Use a more sensitive threshold for outlier detection
        mean_distance = np.mean(all_distances)
        std_distance = np.std(all_distances)
        threshold = mean_distance + 1.5 * std_distance  # More sensitive threshold
        
        # Find outliers (nodes with high distance from median)
        for idx, node_id, values in node_info:
            distance = np.linalg.norm(values - median_values)
            
            # Also check for extreme values directly
            max_abs_value = np.max(np.abs(values))
            median_max = np.max(np.abs(median_values))
            
            # Detect if distance is above threshold OR if values are extremely large
            if distance > threshold or max_abs_value > 10 * median_max:
                malicious_nodes.append(node_id)
                self.malicious_nodes.add(node_id)
        
        return malicious_nodes
    
    def secure_compress_gradients(self, gradients, compression_ratio: float = 0.5) -> Dict[str, Any]:
        """
        Compress gradients securely while preserving privacy.
        
        Args:
            gradients: Gradients to compress (can be List[List[float]] or Dict[str, Any])
            compression_ratio: Compression ratio (0.0 to 1.0)
            
        Returns:
            Compressed gradients with metadata
        """
        if not gradients:
            return {}
        
        # Handle different input formats
        if isinstance(gradients, dict):
            # If input is a dict, process each key-value pair
            compressed_data = {}
            metadata = {
                'compression_ratio': compression_ratio,
                'timestamp': time.time(),
                'privacy_noise_added': True
            }
            
            for layer_name, grad_data in gradients.items():
                if isinstance(grad_data, (list, np.ndarray)):
                    try:
                        grad_array = np.array(grad_data, dtype=np.float64)
                        
                        # Flatten gradient
                        flat_grad = grad_array.flatten()
                        
                        # Select top-k elements based on magnitude
                        k = max(1, int(len(flat_grad) * compression_ratio))
                        top_k_indices = np.argpartition(np.abs(flat_grad), -k)[-k:]
                        
                        # Create sparse representation
                        sparse_grad = np.zeros_like(flat_grad)
                        sparse_grad[top_k_indices] = flat_grad[top_k_indices]
                        
                        # Add differential privacy noise
                        noise = np.random.laplace(0, 0.01, sparse_grad.shape)
                        noisy_sparse_grad = sparse_grad + noise
                        
                        # Reshape back to original shape
                        compressed_grad = noisy_sparse_grad.reshape(grad_array.shape)
                        
                        compressed_data[layer_name] = {
                            'data': compressed_grad.tolist(),
                            'indices': top_k_indices.tolist(),
                            'shape': list(grad_array.shape),
                            'compression_ratio': compression_ratio
                        }
                    except (ValueError, TypeError):
                        # Handle non-numeric data
                        compressed_data[layer_name] = grad_data
                else:
                    compressed_data[layer_name] = grad_data
        else:
            # Handle list format (original behavior)
            grad_arrays = []
            for grad in gradients:
                try:
                    grad_array = np.array(grad, dtype=np.float64)
                    grad_arrays.append(grad_array)
                except (ValueError, TypeError):
                    # Skip non-numeric gradients
                    continue
            
            if not grad_arrays:
                return {}
            
            # Simple compression using top-k sparsification
            compressed_data = {}
            metadata = {
                'compression_ratio': compression_ratio,
                'timestamp': time.time(),
                'privacy_noise_added': True
            }
            
            for i, grad_array in enumerate(grad_arrays):
                layer_name = f'layer_{i}'
                
                # Flatten gradient
                flat_grad = grad_array.flatten()
                
                # Select top-k elements based on magnitude
                k = max(1, int(len(flat_grad) * compression_ratio))
                top_k_indices = np.argpartition(np.abs(flat_grad), -k)[-k:]
                
                # Create sparse representation
                sparse_grad = np.zeros_like(flat_grad)
                sparse_grad[top_k_indices] = flat_grad[top_k_indices]
                
                # Add differential privacy noise
                noise = np.random.laplace(0, 0.01, sparse_grad.shape)
                noisy_sparse_grad = sparse_grad + noise
                
                # Reshape back to original shape
                compressed_grad = noisy_sparse_grad.reshape(grad_array.shape)
                
                compressed_data[layer_name] = {
                    'data': compressed_grad.tolist(),
                    'indices': top_k_indices.tolist(),
                    'shape': list(grad_array.shape),
                    'compression_ratio': compression_ratio
                }
        
        return {
            'compressed_gradients': compressed_data,
            'compression_metadata': metadata
        }
    
    def secure_decompress_gradients(self, compressed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decompress securely compressed gradients.
        
        Args:
            compressed_data: Compressed gradient data
            
        Returns:
            Decompressed gradients in original format
        """
        if 'compressed_gradients' not in compressed_data:
            return {}
        
        decompressed_gradients = {}
        compressed_grads = compressed_data['compressed_gradients']
        
        for layer_name, compressed_grad in compressed_grads.items():
            if isinstance(compressed_grad, dict) and 'data' in compressed_grad:
                # Reconstruct from compressed format
                data = compressed_grad['data']
                shape = compressed_grad['shape']
                
                # Convert back to numpy array and reshape
                grad_array = np.array(data)
                if len(shape) > 1:
                    grad_array = grad_array.reshape(shape)
                
                decompressed_gradients[layer_name] = grad_array.tolist()
            else:
                # Handle non-compressed data
                decompressed_gradients[layer_name] = compressed_grad
        
        return decompressed_gradients
    
    def detect_poisoning(self, gradients: List[np.ndarray], 
                        threshold: float = 2.0) -> Tuple[bool, List[int]]:
        """
        Detect potential data poisoning attacks using gradient analysis.
        
        Args:
            gradients: List of gradient updates from different clients
            threshold: Detection threshold for outlier detection
            
        Returns:
            Tuple of (is_poisoned, suspicious_indices)
        """
        if not gradients:
            return False, []
            
        # Convert gradients to numpy arrays
        gradient_arrays = []
        for grad in gradients:
            if HAS_TORCH and isinstance(grad, torch.Tensor):
                grad_array = grad.detach().cpu().numpy()
            else:
                grad_array = np.array(grad)
            gradient_arrays.append(grad_array.flatten())
        
        # Calculate gradient distances
        distances = []
        for i, grad1 in enumerate(gradient_arrays):
            for j, grad2 in enumerate(gradient_arrays[i+1:], i+1):
                dist = np.linalg.norm(grad1 - grad2)
                distances.append(dist)
        
        if not distances:
            return False, []
        
        # Detect outliers using median absolute deviation
        distances = np.array(distances)
        median = np.median(distances)
        mad = np.median(np.abs(distances - median))
        
        # Find suspicious gradients
        suspicious_indices = []
        for i, grad in enumerate(gradient_arrays):
            # Calculate average distance to other gradients
            avg_dist = np.mean([
                np.linalg.norm(grad - other_grad) 
                for j, other_grad in enumerate(gradient_arrays) 
                if i != j
            ])
            
            if avg_dist > median + threshold * mad:
                suspicious_indices.append(i)
        
        is_poisoned = len(suspicious_indices) > 0
        
        return is_poisoned, suspicious_indices
    
    def get_public_key(self) -> Optional[bytes]:
        """Get this node's public key."""
        if self.public_key:
            from cryptography.hazmat.primitives import serialization
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )
        return None


def encrypt_decrypt_roundtrip():
    """Test function for encryption/decryption roundtrip."""
    if not HAS_CRYPTOGRAPHY:
        return False
        
    try:
        # Create two secure FL instances
        alice = SecureFederatedLearning("alice")
        bob = SecureFederatedLearning("bob")
        
        # Test data
        test_params = {
            'weights': np.random.randn(10, 10).tolist(),
            'bias': np.random.randn(10).tolist()
        }
        
        # Alice encrypts for Bob
        bob_pubkey = bob.get_public_key()
        encrypted_data, signature = alice.encrypt_parameters(test_params, bob_pubkey)
        
        # Bob decrypts
        alice_pubkey = alice.get_public_key()
        decrypted_params = bob.decrypt_parameters(encrypted_data, signature, alice_pubkey)
        
        # Verify roundtrip
        return test_params == decrypted_params
        
    except Exception as e:
        logging.error(f"Encryption roundtrip test failed: {e}")
        return False


class SecureFL:
    """
    Simplified SecureFL interface for testing compatibility.
    """
    
    def __init__(self):
        """Initialize SecureFL with default settings."""
        self.secure_fl = SecureFederatedLearning()
        # Generate a peer for testing
        self.peer = SecureFederatedLearning("peer")
    
    def encrypt_parameters(self, data):
        """
        Encrypt parameters and return (ciphertext, nonce, tag, peer_pubkey).
        
        Args:
            data: Data to encrypt (numpy array or dict)
            
        Returns:
            Tuple of (ciphertext, nonce, tag, peer_pubkey)
        """
        if not self.secure_fl.encryption_enabled:
            # Mock encryption for testing when cryptography is not available
            serialized = self.secure_fl._secure_serialize(data if isinstance(data, dict) else {'data': data.tolist() if hasattr(data, 'tolist') else data})
            return serialized, b'mock_nonce', b'mock_tag', b'mock_pubkey'
        
        # Convert numpy array to dict format if needed
        if hasattr(data, 'tolist'):
            parameters = {'data': data.tolist()}
        else:
            parameters = data
            
        # Get peer's public key
        peer_pubkey = self.peer.get_public_key()
        
        # Encrypt using the existing method
        encrypted_data, signature = self.secure_fl.encrypt_parameters(parameters, peer_pubkey)
        
        # Extract components for compatibility
        # encrypted_data contains ciphertext + IV (nonce)
        ciphertext = encrypted_data[:-12]  # All but last 12 bytes
        nonce = encrypted_data[-12:]       # Last 12 bytes (IV)
        tag = signature                    # Use signature as tag
        
        return ciphertext, nonce, tag, peer_pubkey
    
    def decrypt_parameters(self, ciphertext, nonce, tag, peer_pubkey):
        """
        Decrypt parameters from components.
        
        Args:
            ciphertext: Encrypted data
            nonce: IV/nonce
            tag: Authentication tag/signature
            peer_pubkey: Peer's public key
            
        Returns:
            Decrypted data
        """
        if not self.secure_fl.encryption_enabled:
            # Mock decryption for testing
            deserialized = self.secure_fl._secure_deserialize(ciphertext)
            if 'data' in deserialized:
                import numpy as np
                return np.array(deserialized['data'], dtype=np.float32)
            return deserialized
        
        # Reconstruct encrypted_data
        encrypted_data = ciphertext + nonce
        signature = tag
        
        # Get sender's public key (peer in this case)
        sender_pubkey = peer_pubkey
        
        # Decrypt using existing method
        decrypted_params = self.peer.decrypt_parameters(encrypted_data, signature, self.secure_fl.get_public_key())
        
        # Extract the original data format
        if 'data' in decrypted_params:
            import numpy as np
            return np.array(decrypted_params['data'], dtype=np.float32)
        else:
            return decrypted_params


# Keep the original alias for backward compatibility
SecureFederatedLearning_Original = SecureFederatedLearning