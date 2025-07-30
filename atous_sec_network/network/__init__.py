"""
ATous Secure Network - Network Module
Package containing network-related implementations
"""

# Core network components
from .p2p_recovery import ChurnMitigation

# LoRa components
from .lora_optimizer import LoraAdaptiveEngine, LoraHardwareInterface
from .lora_compat import LoRaOptimizer, LoraOptimizer

# Make modules available for direct import
from . import lora_optimizer
from . import lora_compat

__all__ = [
    # P2P Recovery
    'ChurnMitigation',
    
    # LoRa
    'LoraAdaptiveEngine',
    'LoraHardwareInterface',
    'LoRaOptimizer',
    'LoraOptimizer',  # Alias for backward compatibility
    'lora_optimizer',
    'lora_compat',
]
