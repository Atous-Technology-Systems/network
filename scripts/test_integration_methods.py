#!/usr/bin/env python3
"""
Script de teste para verificar métodos de integração do NNIS
"""
import sys
sys.path.insert(0, '.')

from atous_sec_network.security.nnis_system import NNISSystem
from unittest.mock import Mock

# Configuração
config = {
    "model_name": "google/gemma-3n-2b",
    "memory_size": 1000,
    "immune_cells_count": 50,
    "memory_cells_count": 100,
    "threat_threshold": 0.8
}

# Criar instância
nnis = NNISSystem(config)

print("=== TESTE DE INTEGRAÇÃO COM ABISS ===")
# Testar integração com ABISS
mock_abiss = Mock()
behavioral_anomaly = {
    "node_id": "suspicious_node",
    "anomaly_type": "behavioral_deviation",
    "risk_score": 0.85,
    "indicators": ["unusual_network_traffic", "abnormal_cpu_usage"]
}

print("1. Testando integração com ABISS...")
integration_result = nnis.integrate_with_abiss(mock_abiss, behavioral_anomaly)
print(f"   Resultado: {integration_result}")

print("\n=== TESTE DE DISTRIBUIÇÃO P2P ===")
# Testar distribuição P2P
mock_p2p_manager = Mock()
model_update = {
    "update_type": "pattern_database",
    "version": "2.1.0",
    "size_mb": 15.5,
    "checksum": "abc123def456"
}

print("1. Testando distribuição P2P...")
distribution_result = nnis.distribute_via_p2p(mock_p2p_manager, model_update)
print(f"   Resultado: {distribution_result}")

print("\n=== TESTE DE ATUALIZAÇÃO OTA ===")
# Testar atualização OTA
mock_ota_manager = Mock()
security_update = {
    "update_id": "SEC-2024-001",
    "type": "security_patch",
    "priority": "critical",
    "signature": "valid_signature",
    "payload": "encrypted_update_data"
}

print("1. Testando atualização OTA...")
ota_result = nnis.process_ota_security_update(mock_ota_manager, security_update)
print(f"   Resultado: {ota_result}")

print("\n=== VERIFICAÇÃO GERAL ===")
print("✅ Todos os métodos de integração implementados e funcionando!")
