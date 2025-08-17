#!/usr/bin/env python3
"""
Script de debug para entender problemas com métodos de memória do NNIS
"""
import sys
sys.path.insert(0, '.')

from atous_sec_network.security.nnis_system import NNISSystem
import time

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

print("=== TESTE DE CONSOLIDAÇÃO ===")
# Armazenar padrões similares
similar_patterns = [
    {"indicators": ["file1.exe", "reg_key1"], "confidence": 0.7},
    {"indicators": ["file1.exe", "reg_key2"], "confidence": 0.8},
    {"indicators": ["file1.exe", "reg_key1"], "confidence": 0.9}
]

print("1. Armazenando padrões similares...")
for i, pattern in enumerate(similar_patterns):
    result = nnis.store_in_immune_memory(f"pattern_{i}", pattern)
    print(f"   Pattern {i}: {result}")

print("\n2. Verificando base de dados antes da consolidação...")
print(f"   Padrões na base: {len(nnis.threat_database)}")
for pattern_id, pattern_info in nnis.threat_database.items():
    if "indicators" in pattern_info:
        print(f"   {pattern_id}: {pattern_info['indicators']}")

print("\n3. Executando consolidação...")
consolidated_memory = nnis.consolidate_memory(similarity_threshold=0.8)
print(f"   Resultado: {consolidated_memory}")

print("\n4. Verificando base de dados após consolidação...")
print(f"   Padrões na base: {len(nnis.threat_database)}")
for pattern_id, pattern_info in nnis.threat_database.items():
    if "indicators" in pattern_info:
        print(f"   {pattern_id}: {pattern_info['indicators']}")

print("\n=== TESTE DE ENVELHECIMENTO ===")
print("1. Armazenando padrão antigo...")
old_pattern = {"indicators": ["old_threat.exe"], "confidence": 0.9}
result = nnis.store_in_immune_memory("old_001", old_pattern)
print(f"   Resultado: {result}")

print("\n2. Verificando padrão antes do envelhecimento...")
memory = nnis.get_immune_memory()
if "old_001" in memory:
    print(f"   Confiança antes: {memory['old_001']['confidence']}")

print("\n3. Aplicando envelhecimento...")
aging_result = nnis.apply_memory_aging(aging_factor=0.1)
print(f"   Resultado: {aging_result}")

print("\n4. Verificando padrão após envelhecimento...")
memory = nnis.get_immune_memory()
if "old_001" in memory:
    print(f"   Confiança depois: {memory['old_001']['confidence']}")

print("\n=== TESTE DE ENVELHECIMENTO COM TEMPO SIMULADO ===")
print("1. Armazenando padrão para envelhecimento...")
aging_pattern = {"indicators": ["aging_threat.exe"], "confidence": 0.9}
result = nnis.store_in_immune_memory("aging_001", aging_pattern)
print(f"   Resultado: {result}")

print("\n2. Verificando padrão antes do envelhecimento...")
memory = nnis.get_immune_memory()
if "aging_001" in memory:
    print(f"   Confiança antes: {memory['aging_001']['confidence']}")

print("\n3. Simulando passagem de tempo (30 dias)...")
# Simular tempo passado
original_time = time.time
time.time = lambda: original_time() + (30 * 24 * 3600)

print("\n4. Aplicando envelhecimento com tempo simulado...")
aging_result = nnis.apply_memory_aging(aging_factor=0.1)
print(f"   Resultado: {aging_result}")

print("\n5. Verificando padrão após envelhecimento...")
memory = nnis.get_immune_memory()
if "aging_001" in memory:
    print(f"   Confiança depois: {memory['aging_001']['confidence']}")

# Restaurar tempo original
time.time = original_time

print("\n=== VERIFICAÇÃO GERAL ===")
print(f"Total de padrões na base: {len(nnis.threat_database)}")
print(f"Padrões com indicadores: {sum(1 for p in nnis.threat_database.values() if 'indicators' in p)}")
