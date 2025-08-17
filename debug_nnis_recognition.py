#!/usr/bin/env python3
"""
Script de debug para entender problema de reconhecimento do NNIS
"""
import sys
sys.path.insert(0, '.')

from atous_sec_network.security.nnis_system import NNISSystem

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

# Padrão de ameaça
threat_pattern = {
    "type": "malware_signature",
    "indicators": ["suspicious_file.exe", "registry_modification", "network_beacon"],
    "confidence": 0.85,
    "severity": "high"
}

print("1. Aprendendo padrão...")
result = nnis.learn_threat_pattern("pattern_002", threat_pattern)
print(f"Resultado: {result}")

print("\n2. Verificando memória...")
memory = nnis.get_immune_memory()
print(f"Memória: {memory}")

print("\n3. Verificando base de dados...")
print(f"Base de dados: {nnis.threat_database}")

print("\n4. Dados de entrada para reconhecimento...")
input_data = {
    "file_name": "suspicious_file.exe",
    "registry_changes": ["HKEY_LOCAL_MACHINE\\Software\\Malware"],
    "network_activity": ["beacon_to_c2_server"]
}
print(f"Input: {input_data}")

print("\n5. Normalizando dados de entrada...")
input_indicators = []
for key, value in input_data.items():
    if isinstance(value, list):
        input_indicators.extend(value)
    elif isinstance(value, str):
        input_indicators.append(value)

normalized_input = {"indicators": input_indicators}
print(f"Normalizado: {normalized_input}")

print("\n6. Testando similaridade...")
for pattern_id, pattern_info in nnis.threat_database.items():
    similarity = nnis.calculate_pattern_similarity(normalized_input, pattern_info)
    print(f"Similaridade com {pattern_id}: {similarity}")

print("\n7. Tentando reconhecimento...")
recognition_result = nnis.recognize_threat_pattern(input_data)
print(f"Resultado: {recognition_result}")
