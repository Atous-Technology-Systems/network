#!/usr/bin/env python3
"""
ATous Secure Network - Sistema de Segurança Inteligente

Este módulo implementa um sistema de segurança baseado em IA que combina:
- ABISS (Anomaly-Based Intrusion Security System)
- NNIS (Neural Network Intrusion System) 
- LoRa Optimizer para comunicação eficiente
- P2P Recovery System para recuperação distribuída

O sistema utiliza aprendizado de máquina para detectar anomalias e ameaças
em tempo real, fornecendo proteção adaptativa e inteligente.
"""

__version__ = "1.0.0"
__author__ = "ATous Security Team"
__description__ = "Sistema de Segurança Inteligente com IA"

# Configurar logging centralizado na inicialização do módulo
from .core.logging_config import setup_logging

# Inicializar sistema de logging
_main_logger = setup_logging()
_main_logger.info("🛡️ ATous Secure Network - Módulo Principal Inicializado")
_main_logger.info(f"📦 Versão: {__version__}")

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.absolute())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import submodules to make them accessible
try:
    from . import core
    from . import network
    from . import security
    from . import ml
except ImportError as e:
    # Handle import errors gracefully during development
    import warnings
    warnings.warn(f"Could not import submodule: {e}", ImportWarning)

# Use lazy imports to avoid circular import issues
def _import_model_manager():
    from atous_sec_network.core.model_manager_impl import ModelManager
    return ModelManager

def _import_model_metadata():
    from atous_sec_network.core.model_metadata import ModelMetadata
    return ModelMetadata

def _import_federated_model_updater():
    from atous_sec_network.core.model_manager import FederatedModelUpdater
    return FederatedModelUpdater

# Configurações globais
DEFAULT_CONFIG = {
    "security_level": "high",
    "ml_enabled": True,
    "logging_enabled": True,
    "debug_mode": False
}

# Define __all__ to explicitly specify what gets imported with 'from atous_sec_network import *'
__all__ = [
    # Core components
    'ModelManager',
    'ModelMetadata',
    'FederatedModelUpdater',
    '_import_model_manager',
    '_import_model_metadata',
    '_import_federated_model_updater',
    # Submodules
    'core',
    'network',
    'security',
    'ml',
    'DEFAULT_CONFIG',
    'setup_logging'  # Exportar função de logging
]
