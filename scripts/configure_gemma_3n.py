#!/usr/bin/env python3
"""
Script para configurar o Gemma 3N correto na aplicação
"""

import json
import requests
from pathlib import Path

def verify_gemma_3n_model():
    """Verifica se o modelo Gemma 3N existe e está acessível"""
    model_name = "google/gemma-3n-E4B"
    
    print(f"🔍 Verificando modelo: {model_name}")
    
    try:
        url = f"https://huggingface.co/api/models/{model_name}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            model_info = response.json()
            print(f"✅ Modelo encontrado!")
            print(f"   Downloads: {model_info.get('downloads', 'N/A')}")
            print(f"   Likes: {model_info.get('likes', 'N/A')}")
            print(f"   Última atualização: {model_info.get('lastModified', 'N/A')}")
            return True
        else:
            print(f"❌ Modelo não encontrado (HTTP {response.status_code})")
            return False
            
    except Exception as e:
        print(f"⚠️  Erro ao verificar modelo: {e}")
        return False

def create_gemma_3n_config():
    """Cria configuração otimizada para o Gemma 3N"""
    model_name = "google/gemma-3n-E4B"
    
    config = {
        "model_name": model_name,
        "model_params": {
            "torch_dtype": "float16",
            "device_map": "auto",
            "low_cpu_mem_usage": True,
            "trust_remote_code": True,
            "use_cache": True,
            "attn_implementation": "eager"  # Mais estável para Gemma
        },
        "pipeline_params": {
            "max_length": 512,
            "max_new_tokens": 256,
            "temperature": 0.7,
            "do_sample": True,
            "top_p": 0.9,
            "top_k": 50,
            "repetition_penalty": 1.1,
            "pad_token_id": 0,
            "eos_token_id": 1
        },
        "memory_size": 1000,
        "threat_threshold": 0.7,
        "simulation_mode": False,
        "enable_monitoring": True,
        "learning_rate": 0.01
    }
    
    return config

def update_application_files():
    """Atualiza arquivos da aplicação com Gemma 3N"""
    model_name = "google/gemma-3n-E4B"
    config = create_gemma_3n_config()
    
    # 1. Salvar configuração JSON
    with open("gemma_config.json", "w") as f:
        json.dump(config, f, indent=2)
    print(f"✅ Configuração salva em: gemma_config.json")
    
    # 2. Atualizar __main__.py
    main_file = Path("atous_sec_network/__main__.py")
    if main_file.exists():
        with open(main_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Substituir configuração ABISS
        old_abiss = 'abiss_config = {'
        new_abiss = f'''abiss_config = {{
            "model_name": "{model_name}",
            "model_params": {config["model_params"]},
            "pipeline_params": {config["pipeline_params"]},
            "memory_size": {config["memory_size"]},
            "threat_threshold": {config["threat_threshold"]},
            "simulation_mode": {str(config["simulation_mode"]).lower()},
            "enable_monitoring": {str(config["enable_monitoring"]).lower()},
            "learning_rate": {config["learning_rate"]}
        }}'''
        
        # Encontrar e substituir a configuração ABISS
        import re
        abiss_pattern = r'abiss_config = \{[^}]*\}'
        content = re.sub(abiss_pattern, new_abiss.replace('{', '{{').replace('}', '}}'), content, flags=re.DOTALL)
        
        # Substituir configuração NNIS
        nnis_pattern = r'nnis_config = \{[^}]*\}'
        new_nnis = f'''nnis_config = {{
            "model_name": "{model_name}",
            "model_params": {config["model_params"]},
            "simulation_mode": {str(config["simulation_mode"]).lower()},
            "memory_size": {config["memory_size"]},
            "immune_cell_count": 50,
            "memory_cell_count": 100,
            "threat_threshold": 0.8
        }}'''
        
        content = re.sub(nnis_pattern, new_nnis.replace('{', '{{').replace('}', '}}'), content, flags=re.DOTALL)
        
        with open(main_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ Arquivo {main_file} atualizado")
    
    # 3. Criar arquivo de configuração Python
    config_dir = Path("atous_sec_network/config")
    config_dir.mkdir(exist_ok=True)
    
    config_file = config_dir / "gemma_3n_config.py"
    config_content = f'''"""
Configuração Gemma 3N para ATous Secure Network
Modelo: {model_name}
"""

GEMMA_3N_CONFIG = {{
    "model_name": "{model_name}",
    "model_params": {config["model_params"]},
    "pipeline_params": {config["pipeline_params"]},
    "memory_size": {config["memory_size"]},
    "threat_threshold": {config["threat_threshold"]},
    "simulation_mode": {config["simulation_mode"]},
    "enable_monitoring": {config["enable_monitoring"]},
    "learning_rate": {config["learning_rate"]}
}}

# Configurações específicas para ABISS
ABISS_CONFIG = GEMMA_3N_CONFIG.copy()

# Configurações específicas para NNIS
NNIS_CONFIG = GEMMA_3N_CONFIG.copy()
NNIS_CONFIG.update({{
    "immune_cell_count": 50,
    "memory_cell_count": 100,
    "threat_threshold": 0.8
}})
'''
    
    with open(config_file, 'w', encoding='utf-8') as f:
        f.write(config_content)
    
    print(f"✅ Configuração Python salva em: {config_file}")

def setup_huggingface_auth():
    """Configura autenticação para acessar o Gemma 3N"""
    print("\n🔐 Configurando autenticação Hugging Face...")
    print("O modelo Gemma 3N pode requerer autenticação.")
    
    try:
        import huggingface_hub
        
        # Verificar se já está logado
        try:
            token = huggingface_hub.get_token()
            if token:
                print("✅ Já autenticado no Hugging Face")
                return True
        except:
            pass
        
        print("\n📋 Para acessar o Gemma 3N:")
        print("1. Visite: https://huggingface.co/google/gemma-3n-E4B")
        print("2. Aceite os termos de uso do modelo")
        print("3. Execute: huggingface-cli login")
        print("4. Cole seu token de acesso")
        
        choice = input("\nDeseja fazer login agora? (y/n): ").lower().strip()
        
        if choice in ['y', 'yes', 'sim']:
            try:
                # Usar método Python em vez de CLI
                from huggingface_hub import login
                print("\n🌐 Abrindo login do Hugging Face...")
                login()
                print("✅ Login realizado com sucesso!")
                return True
            except Exception as e:
                print(f"❌ Erro no login: {e}")
                print("   Tente manualmente: python -c \"from huggingface_hub import login; login()\"")
                return True
        else:
            print("⚠️  Login pulado. Você pode fazer depois com: huggingface-cli login")
            return True
            
    except ImportError:
        print("⚠️  huggingface_hub não instalado")
        print("   Instale com: pip install huggingface_hub")
        return False

def main():
    """Função principal"""
    print("🚀 Configurador Gemma 3N - ATous Secure Network")
    print("=" * 60)
    
    # Verificar se o modelo existe
    if not verify_gemma_3n_model():
        print("❌ Não foi possível verificar o modelo Gemma 3N")
        return 1
    
    # Configurar autenticação
    setup_huggingface_auth()
    
    # Atualizar arquivos da aplicação
    print("\n🔧 Atualizando configurações da aplicação...")
    update_application_files()
    
    print("\n✅ Configuração do Gemma 3N concluída!")
    print("\n🎯 Próximos passos:")
    print("1. Se necessário, faça login: huggingface-cli login")
    print("2. Teste a configuração: python start_app.py --full")
    print("3. Verifique os logs para confirmar carregamento")
    print("4. Execute testes: python test_gemma_integration.py")
    
    print(f"\n📊 Informações do modelo:")
    print(f"   Nome: google/gemma-3n-E4B")
    print(f"   Tipo: Gemma 3N (Nova geração)")
    print(f"   URL: https://huggingface.co/google/gemma-3n-E4B")
    print(f"   Tamanho estimado: ~4-8GB")
    
    return 0

if __name__ == "__main__":
    exit(main())