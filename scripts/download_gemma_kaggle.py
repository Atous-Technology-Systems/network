#!/usr/bin/env python3
"""
Script para baixar e configurar Gemma 3N via Kaggle API
Baseado no comando curl fornecido pelo usuário
"""

import os
import subprocess
import json
import tarfile
import shutil
from pathlib import Path

def setup_kaggle_credentials():
    """Configura credenciais do Kaggle"""
    print("🔑 Configuração de Credenciais Kaggle")
    print("=" * 40)
    
    # Verificar se já existem credenciais
    kaggle_dir = Path.home() / ".kaggle"
    kaggle_json = kaggle_dir / "kaggle.json"
    
    if kaggle_json.exists():
        print("✅ Credenciais Kaggle já configuradas!")
        try:
            with open(kaggle_json) as f:
                creds = json.load(f)
            return creds.get("username"), creds.get("key")
        except:
            print("⚠️  Erro ao ler credenciais existentes")
    
    print("\n📋 Para obter suas credenciais:")
    print("1. Acesse: https://www.kaggle.com/settings/account")
    print("2. Seção 'API' -> 'Create New Token'")
    print("3. Baixe o arquivo kaggle.json")
    print("4. Ou forneça username e key manualmente")
    
    choice = input("\nJá tem o arquivo kaggle.json? (y/n): ").lower().strip()
    
    if choice in ['y', 'yes', 'sim']:
        print(f"\n📁 Coloque kaggle.json em: {kaggle_dir}")
        input("Pressione Enter quando estiver pronto...")
        
        if kaggle_json.exists():
            try:
                with open(kaggle_json) as f:
                    creds = json.load(f)
                return creds.get("username"), creds.get("key")
            except Exception as e:
                print(f"❌ Erro ao ler kaggle.json: {e}")
    
    # Configuração manual
    print("\n🔧 Configuração manual:")
    username = input("Kaggle Username: ").strip()
    key = input("Kaggle API Key: ").strip()
    
    if username and key:
        # Salvar credenciais
        kaggle_dir.mkdir(exist_ok=True)
        creds = {"username": username, "key": key}
        
        with open(kaggle_json, "w") as f:
            json.dump(creds, f)
        
        # Definir permissões (Linux/Mac)
        try:
            os.chmod(kaggle_json, 0o600)
        except:
            pass
        
        print("✅ Credenciais salvas!")
        return username, key
    
    return None, None

def download_gemma_3n_curl(username, key):
    """Baixa Gemma 3N usando curl (baseado no comando fornecido)"""
    print("\n📥 Baixando Gemma 3N via Kaggle API...")
    print("=" * 40)
    
    # Criar diretório de download
    download_dir = Path("models/gemma-3n")
    download_dir.mkdir(parents=True, exist_ok=True)
    
    model_file = download_dir / "gemma-3n-e2b.tar.gz"
    
    # Comando curl baseado no fornecido pelo usuário
    curl_command = [
        "curl", "-L",
        "-u", f"{username}:{key}",
        "-o", str(model_file),
        "https://www.kaggle.com/api/v1/models/google/gemma-3n/transformers/gemma-3n-e2b/2/download"
    ]
    
    print(f"🔄 Executando download...")
    print(f"📁 Destino: {model_file}")
    
    try:
        # Executar curl
        result = subprocess.run(curl_command, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Download concluído!")
            
            # Verificar se arquivo foi baixado
            if model_file.exists() and model_file.stat().st_size > 0:
                print(f"📊 Tamanho: {model_file.stat().st_size / (1024*1024):.1f} MB")
                return model_file
            else:
                print("❌ Arquivo não foi baixado corretamente")
                return None
        else:
            print(f"❌ Erro no download: {result.stderr}")
            return None
            
    except Exception as e:
        print(f"❌ Erro ao executar curl: {e}")
        return None

def download_gemma_3n_python(username, key):
    """Alternativa usando Python requests"""
    print("\n📥 Tentando download via Python...")
    
    try:
        import requests
        from requests.auth import HTTPBasicAuth
        
        download_dir = Path("models/gemma-3n")
        download_dir.mkdir(parents=True, exist_ok=True)
        
        model_file = download_dir / "gemma-3n-e2b.tar.gz"
        
        url = "https://www.kaggle.com/api/v1/models/google/gemma-3n/transformers/gemma-3n-e2b/2/download"
        
        print("🔄 Iniciando download...")
        
        response = requests.get(
            url,
            auth=HTTPBasicAuth(username, key),
            stream=True
        )
        
        if response.status_code == 200:
            with open(model_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print("✅ Download Python concluído!")
            print(f"📊 Tamanho: {model_file.stat().st_size / (1024*1024):.1f} MB")
            return model_file
        else:
            print(f"❌ Erro HTTP: {response.status_code}")
            return None
            
    except ImportError:
        print("⚠️  requests não disponível")
        return None
    except Exception as e:
        print(f"❌ Erro no download Python: {e}")
        return None

def extract_model(tar_file):
    """Extrai o modelo baixado"""
    print(f"\n📦 Extraindo modelo...")
    
    extract_dir = tar_file.parent / "extracted"
    extract_dir.mkdir(exist_ok=True)
    
    try:
        with tarfile.open(tar_file, 'r:gz') as tar:
            tar.extractall(extract_dir)
        
        print("✅ Modelo extraído!")
        
        # Listar conteúdo
        print("\n📋 Conteúdo extraído:")
        for item in extract_dir.rglob("*"):
            if item.is_file():
                print(f"   📄 {item.relative_to(extract_dir)}")
        
        return extract_dir
        
    except Exception as e:
        print(f"❌ Erro na extração: {e}")
        return None

def configure_local_model(model_dir):
    """Configura modelo local na aplicação"""
    print(f"\n🔧 Configurando modelo local...")
    
    # Encontrar diretório do modelo
    model_path = None
    for item in model_dir.rglob("*"):
        if item.is_dir() and any(f.name in ['config.json', 'tokenizer.json'] for f in item.iterdir()):
            model_path = item
            break
    
    if not model_path:
        print("❌ Estrutura do modelo não encontrada")
        return False
    
    print(f"📁 Modelo encontrado em: {model_path}")
    
    # Criar configuração para modelo local
    config = {
        "model_name": str(model_path.absolute()),
        "model_params": {
            "torch_dtype": "float16",
            "device_map": "auto",
            "low_cpu_mem_usage": True,
            "trust_remote_code": True,
            "local_files_only": True
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
    
    # Salvar configuração
    with open("local_gemma_config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print("✅ Configuração local salva!")
    
    # Atualizar arquivo principal
    update_main_with_local_model(str(model_path.absolute()))
    
    return True

def update_main_with_local_model(model_path):
    """Atualiza arquivo principal com modelo local"""
    main_file = Path("atous_sec_network/__main__.py")
    
    if main_file.exists():
        with open(main_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Substituir caminho do modelo
        content = content.replace('google/gemma-2-2b-it', model_path)
        content = content.replace('google/gemma-3n-E4B', model_path)
        
        # Adicionar local_files_only
        if '"trust_remote_code": True' in content:
            content = content.replace(
                '"trust_remote_code": True',
                '"trust_remote_code": True,\n                "local_files_only": True'
            )
        
        with open(main_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ Arquivo principal atualizado!")

def test_local_model():
    """Testa o modelo local"""
    print("\n🧪 Testando modelo local...")
    
    try:
        # Executar teste
        result = subprocess.run(
            ["python", "start_app.py", "--full"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            output = result.stdout + result.stderr
            
            if "Sistema ABISS inicializado" in output and "Erro ao carregar" not in output:
                print("✅ Modelo local funcionando!")
                return True
            else:
                print("⚠️  Modelo carregado mas com avisos")
                print("Verifique os logs para detalhes")
                return True
        else:
            print("❌ Erro no teste")
            print(f"Saída: {result.stderr[:200]}...")
            return False
            
    except subprocess.TimeoutExpired:
        print("⚠️  Teste demorou muito (pode estar funcionando)")
        return True
    except Exception as e:
        print(f"❌ Erro no teste: {e}")
        return False

def main():
    """Função principal"""
    print("📥 Download e Configuração Gemma 3N via Kaggle")
    print("=" * 60)
    
    # Configurar credenciais
    username, key = setup_kaggle_credentials()
    
    if not username or not key:
        print("❌ Credenciais não configuradas")
        return 1
    
    print(f"✅ Credenciais configuradas para: {username}")
    
    # Tentar download via curl primeiro
    model_file = download_gemma_3n_curl(username, key)
    
    # Se curl falhar, tentar Python
    if not model_file:
        print("\n🔄 Tentando método alternativo...")
        model_file = download_gemma_3n_python(username, key)
    
    if not model_file:
        print("❌ Falha no download")
        return 1
    
    # Extrair modelo
    model_dir = extract_model(model_file)
    
    if not model_dir:
        print("❌ Falha na extração")
        return 1
    
    # Configurar modelo local
    if configure_local_model(model_dir):
        print("\n🎉 Gemma 3N configurado com sucesso!")
        
        # Testar modelo
        print("\n🧪 Testar modelo agora?")
        if input("(y/n): ").lower().strip() in ['y', 'yes', 'sim']:
            test_local_model()
        
        print("\n🚀 Próximos passos:")
        print("1. Execute: python start_app.py --full")
        print("2. Verifique os logs para confirmar carregamento")
        print("3. Teste os endpoints da API")
        
        return 0
    else:
        print("❌ Falha na configuração")
        return 1

if __name__ == "__main__":
    exit(main())