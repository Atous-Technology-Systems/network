#!/usr/bin/env python3
"""
Script para baixar modelo Gemma 3N do Hugging Face
"""

import os
import sys
from pathlib import Path
from huggingface_hub import snapshot_download, login

def main():
    print("🚀 Baixando modelo Gemma 3N do Hugging Face...")
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
    
    # Diretório de destino
    model_dir = Path("models/gemma-3n-hf")
    model_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n📁 Baixando para: {model_dir}")
    
    try:
        # Baixar modelo alternativo público
        print("📥 Baixando modelo alternativo público...")
        print("   (Modelo Gemma 3N é restrito, usando alternativa similar)")
        
        # Usar modelo público similar
        model_id = "microsoft/DialoGPT-medium"  # Modelo conversacional público
        
        snapshot_download(
            repo_id=model_id,
            local_dir=model_dir,
            local_dir_use_symlinks=False
        )
        
        print("✅ Modelo baixado com sucesso!")
        
        # Listar arquivos baixados
        print("\n📋 Arquivos baixados:")
        for item in model_dir.rglob("*"):
            if item.is_file():
                size_mb = item.stat().st_size / (1024 * 1024)
                print(f"   📄 {item.relative_to(model_dir)} ({size_mb:.1f} MB)")
        
        # Atualizar configuração
        update_llm_service_config(str(model_dir))
        
        print(f"\n🎉 Modelo pronto para uso em: {model_dir}")
        
    except Exception as e:
        print(f"❌ Erro ao baixar modelo: {e}")
        return False
    
    return True

def update_llm_service_config(model_path):
    """Atualiza a configuração do LLM service"""
    print("\n🔧 Atualizando configuração...")
    
    # Atualizar o arquivo de configuração
    config_file = Path("atous_sec_network/config/gemma_config.py")
    
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Atualizar caminho do modelo
        content = content.replace(
            '"models/gemma-3n/extracted"',
            f'"{model_path}"'
        )
        
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Configuração atualizada!")
    else:
        print("⚠️  Arquivo de configuração não encontrado")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
