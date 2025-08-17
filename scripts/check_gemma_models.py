#!/usr/bin/env python3
"""
Script para verificar modelos Gemma disponíveis no Hugging Face
"""

import requests
import json

def check_gemma_models():
    """Verifica modelos Gemma disponíveis"""
    print("🔍 Verificando modelos Gemma disponíveis no Hugging Face...")
    
    # Modelos Gemma conhecidos
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
        "google/gemma-2-27b",
        "google/gemma-2-27b-it"
    ]
    
    available_models = []
    
    for model in gemma_models:
        try:
            url = f"https://huggingface.co/api/models/{model}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                model_info = response.json()
                size = "Unknown"
                
                # Tentar extrair tamanho do nome
                if "2b" in model.lower():
                    size = "2B parameters"
                elif "7b" in model.lower():
                    size = "7B parameters"
                elif "9b" in model.lower():
                    size = "9B parameters"
                elif "27b" in model.lower():
                    size = "27B parameters"
                
                available_models.append({
                    "name": model,
                    "size": size,
                    "downloads": model_info.get("downloads", 0),
                    "likes": model_info.get("likes", 0)
                })
                print(f"✅ {model} - {size}")
            else:
                print(f"❌ {model} - Não encontrado")
                
        except Exception as e:
            print(f"⚠️  {model} - Erro: {str(e)}")
    
    print(f"\n📊 Encontrados {len(available_models)} modelos Gemma disponíveis")
    
    # Recomendar modelos baseado no hardware
    print("\n💡 Recomendações por hardware:")
    print("   🖥️  Desktop/Server (16GB+ RAM): google/gemma-2-9b-it")
    print("   💻 Laptop (8-16GB RAM): google/gemma-2-2b-it")
    print("   📱 Low-end (4-8GB RAM): google/gemma-1.1-2b-it")
    
    return available_models

if __name__ == "__main__":
    models = check_gemma_models()
    
    # Salvar lista de modelos
    with open("available_gemma_models.json", "w") as f:
        json.dump(models, f, indent=2)
    
    print(f"\n💾 Lista salva em: available_gemma_models.json")