"""
ATous Secure Network - Security Module

This module provides comprehensive security features including:
- ABISS (Adaptive Behavioral Intelligence Security System)
- NNIS (Neural Network Immune System)
- Security middleware and authentication
- Input validation and access control
- Key management and cryptographic utilities
"""

# Lazy imports para evitar problemas com dependências pesadas
def get_abiss_system():
    """Retorna a classe ABISSSystem quando necessário"""
    try:
        from .abiss_system import ABISSSystem
        return ABISSSystem
    except ImportError as e:
        # Fallback para configuração básica se transformers não estiver disponível
        print(f"Warning: ABISS system not available due to missing dependencies: {e}")
        return None

def get_nnis_system():
    """Retorna a classe NNISSystem quando necessário"""
    try:
        from .nnis_system import NNISSystem
        return NNISSystem
    except ImportError as e:
        # Fallback para configuração básica se transformers não estiver disponível
        print(f"Warning: NNIS system not available due to missing dependencies: {e}")
        return None

__all__ = [
    'get_abiss_system',
    'get_nnis_system'
]

__version__ = '1.0.0'