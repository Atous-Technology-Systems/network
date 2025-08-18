#!/usr/bin/env python3
"""
Script para configurar o modelo TFLite Gemma 3N
"""

import os
import sys
import shutil
import tarfile
from pathlib import Path

def main():
    print("🔧 Configurando modelo TFLite Gemma 3N...")
    print("=" * 50)
    
    # Caminhos
    tflite_archive = Path("models/gemma-3n/gemma-3n-tflite-gemma-3n-e2b-it-int4-v1.tar.gz")
    extract_dir = Path("models/gemma-3n/extracted")
    
    # 1. Verificar se o arquivo TFLite existe
    if not tflite_archive.exists():
        print(f"❌ Arquivo TFLite não encontrado: {tflite_archive}")
        return False
    
    print(f"✅ Arquivo TFLite encontrado: {tflite_archive}")
    size_gb = tflite_archive.stat().st_size / (1024 * 1024 * 1024)
    print(f"   Tamanho: {size_gb:.1f} GB")
    
    # 2. Criar diretório de extração
    extract_dir.mkdir(parents=True, exist_ok=True)
    print(f"📁 Diretório de extração: {extract_dir}")
    
    # 3. Extrair o modelo
    print("\n📦 Extraindo modelo TFLite...")
    try:
        with tarfile.open(tflite_archive, 'r:gz') as tar:
            tar.extractall(path=extract_dir)
        print("✅ Modelo extraído com sucesso!")
    except Exception as e:
        print(f"❌ Erro ao extrair: {e}")
        return False
    
    # 4. Listar arquivos extraídos
    print("\n📋 Arquivos extraídos:")
    for item in extract_dir.rglob("*"):
        if item.is_file():
            size_mb = item.stat().st_size / (1024 * 1024)
            print(f"   📄 {item.relative_to(extract_dir)} ({size_mb:.1f} MB)")
    
    # 5. Atualizar configurações para usar TFLite
    print("\n🔧 Atualizando configurações...")
    update_configs_for_tflite(str(extract_dir))
    
    # 6. Atualizar LLM service para usar TFLite
    print("\n🔧 Atualizando LLM service...")
    update_llm_service_for_tflite(str(extract_dir))
    
    print("\n🎉 Modelo TFLite Gemma 3N configurado!")
    print(f"📁 Modelo disponível em: {extract_dir}")
    print("\n🔄 Reinicie o servidor para aplicar as mudanças")
    
    return True

def update_configs_for_tflite(model_path):
    """Atualiza as configurações para usar o modelo TFLite"""
    
    # Atualizar gemma_3n_config.py
    config_file = Path("atous_sec_network/config/gemma_3n_config.py")
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Substituir caminhos para usar o modelo TFLite extraído
        old_paths = [
            '"models/gemma-3n/extracted"',
            '"models/gemma-3n-hf"',
            'models/gemma-3n/extracted',
            'models/gemma-3n-hf'
        ]
        
        updated = False
        for old_path in old_paths:
            if old_path in content:
                content = content.replace(old_path, f'"{model_path}"')
                updated = True
        
        if updated:
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print("✅ gemma_3n_config.py atualizado para TFLite")
        else:
            print("ℹ️  gemma_3n_config.py já está correto")

def update_llm_service_for_tflite(model_path):
    """Atualiza o LLM service para usar TFLite"""
    
    # Atualizar o caminho padrão no LLM service
    llm_service_file = Path("atous_sec_network/ml/llm_service.py")
    if llm_service_file.exists():
        with open(llm_service_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Substituir o caminho padrão
        old_default = 'self.model_path = model_path or "models/gemma-3n-hf"'
        new_default = f'self.model_path = model_path or "{model_path}"'
        
        if old_default in content:
            content = content.replace(old_default, new_default)
            with open(llm_service_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print("✅ LLM service atualizado para usar TFLite")
        else:
            print("ℹ️  LLM service já está configurado corretamente")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
