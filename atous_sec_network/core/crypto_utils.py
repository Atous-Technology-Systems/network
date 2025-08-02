"""Cryptographic utilities for secure federated learning.

This module provides reusable cryptographic functions to avoid code duplication
and improve maintainability.
"""

import hashlib
import hmac
import numpy as np
from typing import Tuple, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class CryptoManager:
    """Manages cryptographic operations for secure federated learning."""
    
    # Constants
    SALT = b'secure_fl_salt'
    INFO = b'secure_fl_key'
    KEY_LENGTH = 32
    IV_LENGTH = 12
    
    def __init__(self):
        """Initialize crypto manager."""
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography library is required for secure operations")
    
    def generate_key_pair(self) -> Tuple['EllipticCurvePrivateKey', 'EllipticCurvePublicKey']:
        """Generate ECDH key pair.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key
    
    def derive_shared_key(self, private_key: 'EllipticCurvePrivateKey', 
                         peer_public_key: bytes) -> bytes:
        """Derive shared key using ECDH key exchange.
        
        Args:
            private_key: Local private key
            peer_public_key: Remote public key as bytes
            
        Returns:
            Derived encryption key
        """
        # Reconstruct public key from bytes
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_public_key
        )
        
        # Perform ECDH key exchange
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        
        # Derive encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=self.SALT,
            info=self.INFO,
            backend=default_backend()
        ).derive(shared_key)
        
        return derived_key
    
    def encrypt_data(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-GCM.
        
        Args:
            data: Data to encrypt
            key: Encryption key
            
        Returns:
            Tuple of (encrypted_data_with_iv, signature)
        """
        # Generate random IV
        iv = np.random.bytes(self.IV_LENGTH)
        
        # Encrypt with AES-GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Get authentication tag from GCM
        auth_tag = encryptor.tag
        
        # Combine encrypted data with IV and auth tag
        encrypted_with_iv = encrypted_data + iv + auth_tag
        
        # Create HMAC signature
        signature = hmac.new(
            key, 
            encrypted_with_iv, 
            hashlib.sha256
        ).digest()
        
        return encrypted_with_iv, signature
    
    def decrypt_data(self, encrypted_data_with_iv: bytes, signature: bytes, 
                    key: bytes) -> bytes:
        """Decrypt data using AES-GCM.
        
        Args:
            encrypted_data_with_iv: Encrypted data with IV appended
            signature: HMAC signature
            key: Decryption key
            
        Returns:
            Decrypted data
            
        Raises:
            ValueError: If signature verification fails
        """
        # Verify signature
        expected_signature = hmac.new(
            key,
            encrypted_data_with_iv,
            hashlib.sha256
        ).digest()
        
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid signature - data may be tampered")
        
        # Extract IV, auth tag and ciphertext
        # Format: ciphertext + iv + auth_tag
        auth_tag_length = 16  # GCM auth tag is 16 bytes
        iv = encrypted_data_with_iv[-auth_tag_length-self.IV_LENGTH:-auth_tag_length]
        auth_tag = encrypted_data_with_iv[-auth_tag_length:]
        ciphertext = encrypted_data_with_iv[:-auth_tag_length-self.IV_LENGTH]
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, auth_tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        return decrypted_data
    
    def serialize_public_key(self, public_key: 'EllipticCurvePublicKey') -> bytes:
        """Serialize public key to bytes.
        
        Args:
            public_key: Public key to serialize
            
        Returns:
            Serialized public key
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )


class CryptoUtils:
    """Utility class for cryptographic operations."""
    
    @staticmethod
    def generate_secure_random(length: int) -> bytes:
        """Generate cryptographically secure random bytes.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Secure random bytes
        """
        import secrets
        return secrets.token_bytes(length)
    
    @staticmethod
    def derive_key(password: bytes, salt: bytes, iterations: int = 100000, length: int = 32) -> bytes:
        """Derive key using PBKDF2.
        
        Args:
            password: Password to derive from
            salt: Salt for key derivation
            iterations: Number of iterations
            length: Length of derived key
            
        Returns:
            Derived key
        """
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.backends import default_backend
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            return kdf.derive(password)
        except ImportError:
            # Fallback usando hashlib
            import hashlib
            return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, length)
    
    @staticmethod
    def secure_hash(data: bytes, algorithm: str = "sha256") -> bytes:
        """Generate secure hash of data.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm to use
            
        Returns:
            Hash digest
        """
        if algorithm == "sha256":
            return hashlib.sha256(data).digest()
        elif algorithm == "sha512":
            return hashlib.sha512(data).digest()
        elif algorithm == "sha3-256":
            return hashlib.sha3_256(data).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Compare two byte strings in constant time.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise
        """
        return hmac.compare_digest(a, b)