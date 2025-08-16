#!/usr/bin/env python3
"""
Script para configurar autenticação do Hugging Face
"""

import subprocess
import sys
from pathlib import Path

def check_huggingface_cli():
    """Verifica se huggingface_hub está instalado"""
    try:
        import huggingface_hub
        return True
    except ImportError:
        return False

def install_huggingface_hub():
    """Instala huggingface_hub"""
    print("📦 Instalando huggingface_hub...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "huggingface_hub"])
        print("✅ huggingface_hub instalado com sucesso!")
        return True
    except subprocess.CalledProcessError:
        print("❌ Falha ao instalar huggingface_hub")
        return False

def setup_authentication():
    """Configura autenticação do Hugging Face"""
    print("🔐 Configurando autenticação do Hugging Face...")
    print("\n📋 Opções:")
    print("1. Login interativo (recomendado)")
    print("2. Usar modelo público alternativo")
    print("3. Pular autenticação (modo simulação)")
    
    choice = input("\nEscolha uma opção (1-3): ").strip()
    
    if choice == "1":
        print("\n🌐 Abrindo login do Hugging Face...")
        print("   1. Será aberto um navegador")
        print("   2. Faça login na sua conta Hugging Face")
        print("   3. Aceite os termos do modelo Gemma")
        print("   4. Copie o token gerado")
        
        try:
            subprocess.run([sys.executable, "-m", "huggingface_hub.commands.huggingface_cli", "login"])
            return True
        except Exception as e:
            print(f"❌ Erro no login: {e}")
            return False
    
    elif choice == "2":
        print("\n🔄 Configurando modelo público alternativo...")
        return setup_alternative_model()
    
    elif choice == "3":
        print("\n⚠️  Configurando modo simulação...")
        return setup_simulation_mode()
    
    else:
        print("❌ Opção inválida")
        return False

def setup_alternative_model():
    """Configura modelo alternativo público"""
    # Modelos públicos similares ao Gemma
    alternatives = [
        ("microsoft/DialoGPT-medium", "DialoGPT Medium - Conversacional"),
        ("distilgpt2", "DistilGPT2 - Pequeno e rápido"),
        ("gpt2", "GPT2 - Clássico"),
        ("microsoft/DialoGPT-small", "DialoGPT Small - Muito rápido")
    ]
    
    print("\n📋 Modelos alternativos disponíveis:")
    for i, (model, desc) in enumerate(alternatives, 1):
        print(f"   {i}. {model} - {desc}")
    
    choice = input("\nEscolha um modelo (1-4): ").strip()
    
    try:
        choice_num = int(choice)
        if 1 <= choice_num <= len(alternatives):
            selected_model = alternatives[choice_num - 1][0]
            
            # Atualizar configuração
            update_config_with_model(selected_model)
            return True
        else:
            print("❌ Escolha inválida")
            return False
    except ValueError:
        print("❌ Entrada inválida")
        return False

def setup_simulation_mode():
    """Configura modo simulação"""
    update_config_with_simulation()
    return True

def update_config_with_model(model_name):
    """Atualiza configuração com novo modelo"""
    config = {
        "model_name": model_name,
        "model_params": {
            "torch_dtype": "float32",
            "device_map": "auto",
            "low_cpu_mem_usage": True,
            "trust_remote_code": False  # Modelos públicos não precisam
        },
        "pipeline_params": {
            "max_length": 256,
            "temperature": 0.7,
            "do_sample": True,
            "top_p": 0.9,
            "pad_token_id": 50256  # Token padrão para GPT
        },
        "memory_size": 1000,
        "threat_threshold": 0.7,
        "simulation_mode": False
    }
    
    # Salvar configuração
    import json
    with open("gemma_config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"✅ Configuração atualizada com modelo: {model_name}")

def update_config_with_simulation():
    """Atualiza configuração para modo simulação"""
    config = {
        "model_name": "simulation-model",
        "model_params": {},
        "pipeline_params": {},
        "memory_size": 1000,
        "threat_threshold": 0.7,
        "simulation_mode": True
    }
    
    # Salvar configuração
    import json
    with open("gemma_config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print("✅ Configuração atualizada para modo simulação")

def fix_python_syntax():
    """Corrige erro de sintaxe no arquivo de configuração"""
    main_file = Path("atous_sec_network/__main__.py")
    
    if main_file.exists():
        with open(main_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Corrigir false/true para False/True
        content = content.replace('"simulation_mode": false', '"simulation_mode": False')
        content = content.replace('"simulation_mode": true', '"simulation_mode": True')
        content = content.replace('false}', 'False}')
        content = content.replace('true}', 'True}')
        
        with open(main_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Corrigido erro de sintaxe Python")

def main():
    """Função principal"""
    print("🔐 Configurador de Autenticação Hugging Face")
    print("=" * 50)
    
    # Corrigir sintaxe primeiro
    fix_python_syntax()
    
    # Verificar huggingface_hub
    if not check_huggingface_cli():
        if not install_huggingface_hub():
            print("❌ Não foi possível instalar huggingface_hub")
            return 1
    
    # Configurar autenticação
    if setup_authentication():
        print("\n✅ Configuração concluída!")
        print("\n🚀 Próximos passos:")
        print("1. Execute: python update_model_configs.py")
        print("2. Teste: python test_gemma_integration.py")
        return 0
    else:
        print("\n❌ Configuração falhou!")
        return 1

if __name__ == "__main__":
    sys.exit(main())