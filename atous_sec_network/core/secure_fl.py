"""
Secure Federated Learning Module

This module provides secure federated learning capabilities including:
- End-to-end encryption of federated parameters
- AES-GCM encryption with ECDH key exchange
- Protection against data poisoning attacks
"""

import hashlib
import hmac
import logging
from typing import Dict, List, Optional, Tuple, Any
import numpy as np

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    logging.warning("cryptography library not available - secure FL disabled")

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    logging.warning("PyTorch not available - secure FL disabled")


class SecureFederatedLearning:
    """
    Secure Federated Learning implementation with encryption and poisoning detection.
    """
    
    def __init__(self, node_id: str, encryption_enabled: bool = True):
        """
        Initialize secure federated learning.
        
        Args:
            node_id: Unique identifier for this node
            encryption_enabled: Whether to enable encryption
        """
        self.node_id = node_id
        self.encryption_enabled = encryption_enabled and HAS_CRYPTOGRAPHY
        self.logger = logging.getLogger(__name__)
        
        if self.encryption_enabled:
            # Generate ECDH key pair
            self.private_key = ec.generate_private_key(
                ec.SECP256R1(), default_backend()
            )
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = None
            self.public_key = None
    
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
            # Serialize parameters
            if HAS_TORCH:
                import torch
                serialized = torch.save(parameters)
            else:
                import pickle
                serialized = pickle.dumps(parameters)
            
            # Perform ECDH key exchange
            shared_key = self.private_key.exchange(
                ec.ECDH(), 
                ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), recipient_public_key
                )
            )
            
            # Derive encryption key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'secure_fl_salt',
                info=b'secure_fl_key',
                backend=default_backend()
            ).derive(shared_key)
            
            # Generate random IV
            iv = np.random.bytes(12)
            
            # Encrypt with AES-GCM
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            encrypted_data = encryptor.update(serialized) + encryptor.finalize()
            
            # Create signature
            signature = hmac.new(
                derived_key, 
                encrypted_data + iv, 
                hashlib.sha256
            ).digest()
            
            return encrypted_data + iv, signature
            
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
            # Extract IV (last 12 bytes)
            iv = encrypted_data[-12:]
            ciphertext = encrypted_data[:-12]
            
            # Perform ECDH key exchange
            shared_key = self.private_key.exchange(
                ec.ECDH(),
                ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), sender_public_key
                )
            )
            
            # Derive decryption key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'secure_fl_salt',
                info=b'secure_fl_key',
                backend=default_backend()
            ).derive(shared_key)
            
            # Verify signature
            expected_signature = hmac.new(
                derived_key,
                encrypted_data,
                hashlib.sha256
            ).digest()
            
            if not hmac.compare_digest(signature, expected_signature):
                raise ValueError("Invalid signature")
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(derived_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Deserialize parameters
            if HAS_TORCH:
                import torch
                return torch.load(decrypted_data)
            else:
                import pickle
                return pickle.loads(decrypted_data)
                
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
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