#!/usr/bin/env python3
"""
Script para debugar o carregamento do modelo LLM
"""

import os
import sys
from pathlib import Path

# Adicionar o projeto ao path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def main():
    print("🔍 Debugando carregamento do modelo LLM...")
    print("=" * 50)
    
    # 1. Verificar variáveis de ambiente
    print("\n1️⃣ Verificando variáveis de ambiente:")
    env_vars = [
        'GEMMA_MODEL_PATH',
        'MODEL_PATH', 
        'LLM_MODEL_PATH',
        'PYTHONPATH'
    ]
    
    for var in env_vars:
        value = os.getenv(var)
        if value:
            print(f"   {var}: {value}")
        else:
            print(f"   {var}: não definida")
    
    # 2. Verificar diretório do modelo
    print("\n2️⃣ Verificando diretório do modelo:")
    model_dir = Path("models/gemma-3n-hf")
    if model_dir.exists():
        print(f"   ✅ Diretório existe: {model_dir}")
        
        # Listar arquivos principais
        key_files = [
            'pytorch_model.bin',
            'config.json', 
            'tokenizer_config.json',
            'vocab.json'
        ]
        
        for file in key_files:
            file_path = model_dir / file
            if file_path.exists():
                size_mb = file_path.stat().st_size / (1024 * 1024)
                print(f"   ✅ {file}: {size_mb:.1f} MB")
            else:
                print(f"   ❌ {file}: não encontrado")
    else:
        print(f"   ❌ Diretório não existe: {model_dir}")
    
    # 3. Verificar configuração do LLM service
    print("\n3️⃣ Verificando configuração do LLM service:")
    try:
        from atous_sec_network.ml.llm_service import LLMService
        
        # Criar instância para teste
        llm_service = LLMService()
        print(f"   Model path configurado: {llm_service.model_path}")
        print(f"   Model path absoluto: {Path(llm_service.model_path).absolute()}")
        print(f"   Model path existe: {Path(llm_service.model_path).exists()}")
        
        # Verificar se o caminho está correto
        expected_path = Path("models/gemma-3n-hf").absolute()
        actual_path = Path(llm_service.model_path).absolute()
        
        if expected_path == actual_path:
            print("   ✅ Caminho do modelo está correto")
        else:
            print(f"   ❌ Caminho incorreto!")
            print(f"      Esperado: {expected_path}")
            print(f"      Atual:   {actual_path}")
            
    except Exception as e:
        print(f"   ❌ Erro ao verificar LLM service: {e}")
    
    # 4. Verificar se há conflitos de configuração
    print("\n4️⃣ Verificando arquivos de configuração:")
    config_files = [
        "atous_sec_network/config/gemma_3n_config.py",
        "atous_sec_network/config/gemma_config.py",
        ".env"
    ]
    
    for config_file in config_files:
        config_path = Path(config_file)
        if config_path.exists():
            print(f"   📄 {config_file}: existe")
            
            # Verificar se contém referências a DialoGPT
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'DialoGPT' in content:
                        print(f"      ⚠️  Contém referências a DialoGPT")
                    if 'gemma-3n' in content.lower():
                        print(f"      ✅ Contém referências a Gemma 3N")
            except Exception as e:
                print(f"      ❌ Erro ao ler: {e}")
        else:
            print(f"   ❌ {config_file}: não existe")
    
    # 5. Testar carregamento do modelo
    print("\n5️⃣ Testando carregamento do modelo:")
    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM
        
        model_path = str(model_dir.absolute())
        print(f"   Tentando carregar de: {model_path}")
        
        # Carregar tokenizer
        print("   Carregando tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(
            model_path,
            trust_remote_code=True,
            local_files_only=True
        )
        print(f"   ✅ Tokenizer carregado: {type(tokenizer).__name__}")
        
        # Carregar modelo
        print("   Carregando modelo...")
        model = AutoModelForCausalLM.from_pretrained(
            model_path,
            torch_dtype="auto",
            device_map="auto",
            trust_remote_code=True,
            local_files_only=True
        )
        print(f"   ✅ Modelo carregado: {type(model).__name__}")
        
        # Verificar informações do modelo
        print(f"   📊 Configuração do modelo:")
        print(f"      Nome: {model.config.name_or_path}")
        print(f"      Tipo: {model.config.model_type}")
        print(f"      Vocab size: {model.config.vocab_size}")
        
    except Exception as e:
        print(f"   ❌ Erro ao carregar modelo: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n🎯 Debug concluído!")

if __name__ == "__main__":
    main()
