"""
ATous Secure Network - Security Module

This module provides comprehensive security features including:
- ABISS (Adaptive Behavioral Intelligence Security System)
- NNIS (Neural Network Immune System)
- Security middleware and authentication
- Input validation and access control
- Key management and cryptographic utilities
"""

from .abiss_system import ABISSSystem
from .nnis_system import NNISSystem

__all__ = [
    'ABISSSystem',
    'NNISSystem'
]

__version__ = '1.0.0'