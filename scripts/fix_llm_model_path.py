#!/usr/bin/env python3
"""
Script simples para corrigir o caminho do modelo LLM
"""

import os
import sys
from pathlib import Path

def main():
    print("🔧 Corrigindo caminho do modelo LLM...")
    print("=" * 50)
    
    # Verificar se o diretório do modelo existe
    model_dir = Path("models/gemma-3n-hf")
    if not model_dir.exists():
        print(f"❌ Diretório do modelo não encontrado: {model_dir}")
        print("   Execute primeiro: python scripts/fix_gemma_3n_setup.py")
        return False
    
    print(f"✅ Diretório do modelo encontrado: {model_dir}")
    
    # Verificar se contém arquivos do modelo
    model_files = list(model_dir.glob("*.bin")) + list(model_dir.glob("*.json"))
    if not model_files:
        print("❌ Nenhum arquivo de modelo encontrado no diretório")
        return False
    
    print(f"✅ {len(model_files)} arquivos de modelo encontrados")
    
    # Atualizar configurações
    update_configs(str(model_dir))
    
    print("\n🎉 Configuração corrigida!")
    print(f"📁 Modelo configurado para usar: {model_dir}")
    print("\n🔄 Reinicie o servidor para aplicar as mudanças")
    
    return True

def update_configs(model_path):
    """Atualiza as configurações para usar o caminho correto"""
    print("\n🔧 Atualizando configurações...")
    
    # 1. Atualizar gemma_3n_config.py
    config_file = Path("atous_sec_network/config/gemma_3n_config.py")
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Substituir caminhos incorretos
        old_paths = [
            '"models/gemma-3n/extracted"',
            '"models/gemma-3n"',
            'models/gemma-3n/extracted'
        ]
        
        updated = False
        for old_path in old_paths:
            if old_path in content:
                content = content.replace(old_path, f'"{model_path}"')
                updated = True
        
        if updated:
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print("✅ gemma_3n_config.py atualizado")
        else:
            print("ℹ️  gemma_3n_config.py já está correto")
    
    # 2. Verificar se o LLM service está configurado corretamente
    llm_service_file = Path("atous_sec_network/ml/llm_service.py")
    if llm_service_file.exists():
        with open(llm_service_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Verificar se o caminho padrão está correto
        if f'"{model_path}"' in content or model_path in content:
            print("✅ LLM service já configurado corretamente")
        else:
            print("⚠️  LLM service pode precisar de atualização manual")
    
    # 3. Verificar se há variáveis de ambiente
    env_file = Path(".env")
    if env_file.exists():
        with open(env_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Substituir variáveis de ambiente relacionadas ao modelo
        old_env_vars = [
            'GEMMA_MODEL_PATH=models/gemma-3n',
            'MODEL_PATH=models/gemma-3n',
            'LLM_MODEL_PATH=models/gemma-3n'
        ]
        
        updated = False
        for old_var in old_env_vars:
            if old_var in content:
                new_var = old_var.replace('models/gemma-3n', model_path)
                content = content.replace(old_var, new_var)
                updated = True
        
        if updated:
            with open(env_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print("✅ .env atualizado")
        else:
            print("ℹ️  .env não precisa de atualização")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
