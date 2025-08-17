#!/usr/bin/env python3
"""
Script de debug para verificar configuração do NNIS
"""
import sys
sys.path.insert(0, '.')

from atous_sec_network.security.nnis_system import NNISSystem

# Configuração de teste
config = {
    "model_name": "google/gemma-3n-2b",
    "memory_size": 2000,
    "immune_cells_count": 100,
    "memory_cells_count": 200,
    "threat_threshold": 0.9
}

print("Configuração:", config)
print("Configuração keys:", list(config.keys()))

# Criar instância
nnis = NNISSystem(config)

print("\nValores retornados pelos métodos:")
print(f"get_memory_size(): {nnis.get_memory_size()}")
print(f"get_immune_cell_count(): {nnis.get_immune_cell_count()}")
print(f"get_memory_cell_count(): {nnis.get_memory_cell_count()}")
print(f"get_threat_threshold(): {nnis.get_threat_threshold()}")

print("\nConfiguração interna:")
print(f"nnis.config: {nnis.config}")
print(f"nnis.config.get('memory_cells_count'): {nnis.config.get('memory_cells_count')}")
print(f"nnis.config.get('memory_cells_count', 50): {nnis.config.get('memory_cells_count', 50)}")
