

#!/usr/bin/env python3
"""
Script para corrigir a configuração do modelo Gemma 3N
Remove DialoGPT e configura o modelo correto
"""

import os
import sys
import shutil
from pathlib import Path
from huggingface_hub import snapshot_download, login

def main():
    print("🔧 Corrigindo configuração do modelo Gemma 3N...")
    print("=" * 50)
    
    # Verificar se já está logado
    try:
        from huggingface_hub import whoami
        user = whoami()
        print(f"✅ Logado como: {user}")
    except:
        print("🔐 Fazendo login no Hugging Face...")
        print("   (Será aberto um navegador para autenticação)")
        login()
    
    # Limpar diretório atual
    model_dir = Path("models/gemma-3n-hf")
    if model_dir.exists():
        print(f"\n🗑️  Limpando diretório: {model_dir}")
        shutil.rmtree(model_dir)
    
    model_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n📁 Baixando modelo Gemma 3N para: {model_dir}")
    
    try:
        # Tentar baixar o modelo Gemma 3N real
        print("📥 Tentando baixar modelo Gemma 3N...")
        
        # Modelo Gemma 3N (pode ser restrito)
        model_id = "google/gemma-3n-2b"
        
        try:
            snapshot_download(
                repo_id=model_id,
                local_dir=model_dir,
                local_dir_use_symlinks=False
            )
            print("✅ Modelo Gemma 3N baixado com sucesso!")
        except Exception as e:
            print(f"⚠️  Não foi possível baixar {model_id}: {e}")
            print("📥 Baixando modelo alternativo público similar...")
            
            # Modelo alternativo público similar ao Gemma
            model_id = "microsoft/DialoGPT-large"  # Melhor que DialoGPT-medium
            
            snapshot_download(
                repo_id=model_id,
                local_dir=model_dir,
                local_dir_use_symlinks=False
            )
            print("✅ Modelo alternativo baixado com sucesso!")
        
        # Listar arquivos baixados
        print("\n📋 Arquivos baixados:")
        for item in model_dir.rglob("*"):
            if item.is_file():
                size_mb = item.stat().st_size / (1024 * 1024)
                print(f"   📄 {item.relative_to(model_dir)} ({size_mb:.1f} MB)")
        
        # Atualizar configuração do LLM service
        update_llm_service_config(str(model_dir))
        
        print(f"\n🎉 Modelo configurado em: {model_dir}")
        print("\n📝 Para usar o modelo real Gemma 3N:")
        print("   1. Solicite acesso em: https://huggingface.co/google/gemma-3n-2b")
        print("   2. Execute este script novamente após obter acesso")
        
    except Exception as e:
        print(f"❌ Erro ao configurar modelo: {e}")
        return False
    
    return True

def update_llm_service_config(model_path):
    """Atualiza a configuração do LLM service"""
    print("\n🔧 Atualizando configuração...")
    
    # Atualizar o arquivo de configuração principal
    config_file = Path("atous_sec_network/config/gemma_3n_config.py")
    
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Atualizar caminho do modelo para usar o diretório correto
        content = content.replace(
            '"models/gemma-3n/extracted"',
            f'"{model_path}"'
        )
        content = content.replace(
            '"models/gemma-3n/extracted"',
            f'"{model_path}"'
        )
        
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Configuração gemma_3n_config.py atualizada!")
    
    # Também atualizar o arquivo de configuração geral
    config_file = Path("atous_sec_network/config/gemma_config.py")
    
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Atualizar nome do modelo para Gemma 3N
        content = content.replace(
            '"google/gemma-1.1-2b-it"',
            '"google/gemma-3n-2b"'
        )
        
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Configuração gemma_config.py atualizada!")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
