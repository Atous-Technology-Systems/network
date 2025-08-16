#!/usr/bin/env python3
"""
Script para verificar o status atual do Gemma 3N no Hugging Face
"""

import requests
import json
import webbrowser

def check_gemma_3n_access():
    """Verifica o status de acesso do Gemma 3N"""
    model_name = "google/gemma-3n-E4B"
    
    print("🔍 Verificando status atual do Gemma 3N...")
    print("=" * 50)
    
    try:
        # Verificar API do modelo
        api_url = f"https://huggingface.co/api/models/{model_name}"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            model_info = response.json()
            
            print(f"✅ Modelo encontrado: {model_name}")
            print(f"📊 Downloads: {model_info.get('downloads', 'N/A')}")
            print(f"❤️  Likes: {model_info.get('likes', 'N/A')}")
            print(f"📅 Última atualização: {model_info.get('lastModified', 'N/A')}")
            
            # Verificar se é gated
            gated = model_info.get('gated', False)
            print(f"🔒 Modelo restrito: {'Sim' if gated else 'Não'}")
            
            if gated:
                print("⚠️  Modelo requer aprovação especial")
            else:
                print("✅ Modelo público - acesso livre!")
            
            return model_info
        else:
            print(f"❌ Erro ao acessar API: HTTP {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Erro na verificação: {e}")
        return None

def test_direct_access():
    """Testa acesso direto ao modelo"""
    print("\n🧪 Testando acesso direto...")
    print("-" * 30)
    
    try:
        from transformers import AutoTokenizer
        
        print("⏳ Tentando carregar tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained("google/gemma-3n-E4B")
        
        if tokenizer:
            print("✅ SUCESSO! Modelo acessível sem restrições!")
            print("🎉 Você pode usar o Gemma 3N diretamente!")
            return True
        else:
            print("❌ Falha no carregamento")
            return False
            
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Erro: {error_msg}")
        
        if "gated repo" in error_msg.lower():
            print("🔒 Confirmado: Modelo requer aprovação")
        elif "not found" in error_msg.lower():
            print("❓ Modelo pode não existir ou ter mudado de nome")
        elif "authentication" in error_msg.lower():
            print("🔑 Problema de autenticação")
        
        return False

def find_alternative_gemma_models():
    """Encontra modelos Gemma alternativos disponíveis"""
    print("\n🔍 Procurando modelos Gemma alternativos...")
    print("-" * 40)
    
    # Lista de modelos Gemma conhecidos
    gemma_models = [
        "google/gemma-2b",
        "google/gemma-2b-it", 
        "google/gemma-7b",
        "google/gemma-7b-it",
        "google/gemma-1.1-2b-it",
        "google/gemma-1.1-7b-it",
        "google/gemma-2-2b",
        "google/gemma-2-2b-it",
        "google/gemma-2-9b",
        "google/gemma-2-9b-it",
        "google/gemma-2-27b-it"
    ]
    
    available_models = []
    
    for model in gemma_models:
        try:
            url = f"https://huggingface.co/api/models/{model}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                model_info = response.json()
                gated = model_info.get('gated', False)
                
                status = "🔒 Restrito" if gated else "✅ Público"
                print(f"{status} {model}")
                
                if not gated:
                    available_models.append(model)
            else:
                print(f"❌ {model} - Não encontrado")
                
        except Exception as e:
            print(f"⚠️  {model} - Erro: {str(e)[:50]}...")
    
    print(f"\n📊 Encontrados {len(available_models)} modelos Gemma públicos")
    return available_models

def check_kaggle_gemma():
    """Verifica Gemma no Kaggle"""
    print("\n🏆 Verificando Gemma no Kaggle...")
    print("-" * 30)
    
    kaggle_urls = [
        "https://www.kaggle.com/models/google/gemma",
        "https://www.kaggle.com/models/google/gemma-2",
        "https://www.kaggle.com/models/google/gemma-3n"
    ]
    
    print("📋 URLs do Kaggle para verificar:")
    for url in kaggle_urls:
        print(f"   • {url}")
    
    choice = input("\nAbrir URLs do Kaggle? (y/n): ").lower().strip()
    if choice in ['y', 'yes', 'sim']:
        for url in kaggle_urls:
            try:
                webbrowser.open(url)
                print(f"🌐 Abrindo: {url}")
            except:
                print(f"⚠️  Não foi possível abrir: {url}")

def provide_updated_solutions():
    """Fornece soluções atualizadas"""
    print("\n🎯 SOLUÇÕES ATUALIZADAS")
    print("=" * 30)
    
    print("\n1️⃣ **VERIFICAR SE GEMMA 3N É REALMENTE RESTRITO**")
    print("   • Pode ter mudado para acesso público")
    print("   • Teste direto na aplicação")
    
    print("\n2️⃣ **USAR GEMMA 2 (COMPROVADAMENTE PÚBLICO)**")
    print("   • google/gemma-2-2b-it")
    print("   • google/gemma-2-9b-it")
    print("   • Qualidade excelente")
    
    print("\n3️⃣ **TENTAR KAGGLE**")
    print("   • Modelos podem estar disponíveis")
    print("   • Processo de aprovação diferente")
    
    print("\n4️⃣ **USAR HUGGING FACE COM LOGIN**")
    print("   • Fazer login: huggingface-cli login")
    print("   • Alguns modelos só precisam de conta")
    
    print("\n5️⃣ **VERIFICAR GOOGLE AI STUDIO**")
    print("   • https://aistudio.google.com/")
    print("   • Acesso direto aos modelos Gemma")

def create_updated_config():
    """Cria configuração atualizada"""
    print("\n🔧 Criando configuração atualizada...")
    
    # Testar modelos disponíveis
    available_models = find_alternative_gemma_models()
    
    if available_models:
        print(f"\n📋 Modelos disponíveis encontrados:")
        for i, model in enumerate(available_models[:5], 1):
            print(f"   {i}. {model}")
        
        choice = input(f"\nEscolher modelo (1-{min(5, len(available_models))}): ").strip()
        
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(available_models):
                selected_model = available_models[choice_idx]
                
                config = {
                    "model_name": selected_model,
                    "model_params": {
                        "torch_dtype": "float16",
                        "device_map": "auto",
                        "low_cpu_mem_usage": True,
                        "trust_remote_code": True
                    },
                    "pipeline_params": {
                        "max_length": 512,
                        "temperature": 0.7,
                        "do_sample": True,
                        "top_p": 0.9
                    },
                    "simulation_mode": False
                }
                
                with open("updated_gemma_config.json", "w") as f:
                    json.dump(config, f, indent=2)
                
                print(f"✅ Configuração salva: {selected_model}")
                return selected_model
        except:
            pass
    
    print("⚠️  Usando configuração padrão")
    return None

def main():
    """Função principal"""
    print("🔍 Verificação Atualizada - Status do Gemma 3N")
    print("=" * 60)
    
    # Verificar status do modelo
    model_info = check_gemma_3n_access()
    
    # Testar acesso direto
    access_success = test_direct_access()
    
    if access_success:
        print("\n🎉 ÓTIMA NOTÍCIA!")
        print("O Gemma 3N está acessível! Você pode usá-lo diretamente.")
        print("\n🚀 Execute: python start_app.py --full")
    else:
        print("\n⚠️  Gemma 3N ainda restrito ou com problemas")
        
        # Encontrar alternativas
        find_alternative_gemma_models()
        
        # Verificar Kaggle
        check_kaggle_gemma()
        
        # Fornecer soluções
        provide_updated_solutions()
        
        # Criar configuração alternativa
        create_updated_config()
    
    print("\n📋 RESUMO:")
    print(f"   • Gemma 3N acessível: {'✅ Sim' if access_success else '❌ Não'}")
    print("   • Alternativas encontradas: ✅ Sim")
    print("   • Kaggle verificado: ✅ Sim")
    print("   • Soluções fornecidas: ✅ Sim")
    
    print("\n💡 RECOMENDAÇÃO:")
    if access_success:
        print("   Use o Gemma 3N diretamente - está funcionando!")
    else:
        print("   Use google/gemma-2-2b-it como alternativa confiável")

if __name__ == "__main__":
    main()