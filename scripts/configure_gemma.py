#!/usr/bin/env python3
"""
Script para configurar modelos Gemma na aplicação ATous Secure Network
"""

import json
import psutil
from pathlib import Path

def get_system_specs():
    """Obtém especificações do sistema"""
    memory_gb = psutil.virtual_memory().total / (1024**3)
    cpu_count = psutil.cpu_count()
    
    return {
        "memory_gb": memory_gb,
        "cpu_count": cpu_count
    }

def recommend_gemma_model():
    """Recomenda modelo Gemma baseado no hardware"""
    specs = get_system_specs()
    memory_gb = specs["memory_gb"]
    
    print(f"🖥️  Sistema detectado:")
    print(f"   RAM: {memory_gb:.1f} GB")
    print(f"   CPUs: {specs['cpu_count']}")
    
    if memory_gb >= 32:
        model = "google/gemma-2-9b-it"
        category = "High-end"
        description = "Modelo grande, melhor qualidade"
    elif memory_gb >= 16:
        model = "google/gemma-2-2b-it"
        category = "Medium"
        description = "Modelo médio, bom equilíbrio"
    elif memory_gb >= 8:
        model = "google/gemma-1.1-2b-it"
        category = "Low-medium"
        description = "Modelo pequeno, mais rápido"
    else:
        model = "google/gemma-1.1-2b-it"
        category = "Low-end"
        description = "Modelo pequeno, otimizado para recursos limitados"
    
    print(f"\n💡 Recomendação: {model}")
    print(f"   Categoria: {category}")
    print(f"   Descrição: {description}")
    
    return model

def create_model_config(model_name):
    """Cria configuração otimizada para o modelo"""
    config = {
        "model_name": model_name,
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
            "top_p": 0.9,
            "pad_token_id": 0
        },
        "memory_size": 1000,
        "threat_threshold": 0.7,
        "simulation_mode": False  # Usar modelo real
    }
    
    # Ajustar configurações baseado no modelo
    if "2b" in model_name:
        config["pipeline_params"]["max_length"] = 256
        config["model_params"]["torch_dtype"] = "float32"  # Mais estável para modelos pequenos
    elif "9b" in model_name:
        config["pipeline_params"]["max_length"] = 1024
        config["model_params"]["torch_dtype"] = "float16"
    
    return config

def update_application_config(model_name):
    """Atualiza configuração da aplicação"""
    config = create_model_config(model_name)
    
    # Salvar configuração
    config_file = Path("gemma_config.json")
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"💾 Configuração salva em: {config_file}")
    
    # Criar arquivo de configuração Python
    python_config = f'''"""
Configuração Gemma para ATous Secure Network
Gerado automaticamente por configure_gemma.py
"""

GEMMA_CONFIG = {{
    "abiss_config": {{
        "model_name": "{model_name}",
        "model_params": {config["model_params"]},
        "pipeline_params": {config["pipeline_params"]},
        "memory_size": {config["memory_size"]},
        "threat_threshold": {config["threat_threshold"]},
        "simulation_mode": {str(config["simulation_mode"]).lower()}
    }},
    "nnis_config": {{
        "model_name": "{model_name}",
        "model_params": {config["model_params"]},
        "memory_size": {config["memory_size"]},
        "simulation_mode": {str(config["simulation_mode"]).lower()}
    }}
}}
'''
    
    config_py_file = Path("atous_sec_network/config/gemma_config.py")
    config_py_file.parent.mkdir(exist_ok=True)
    
    with open(config_py_file, "w") as f:
        f.write(python_config)
    
    print(f"🐍 Configuração Python salva em: {config_py_file}")
    
    return config

def main():
    """Função principal"""
    print("🚀 Configurador de Modelos Gemma - ATous Secure Network")
    print("=" * 60)
    
    # Recomendar modelo
    recommended_model = recommend_gemma_model()
    
    # Perguntar ao usuário
    print(f"\n❓ Deseja usar o modelo recomendado '{recommended_model}'? (y/n): ", end="")
    choice = input().lower().strip()
    
    if choice in ['n', 'no', 'não']:
        print("\n📋 Modelos disponíveis:")
        models = [
            ("google/gemma-1.1-2b-it", "2B - Rápido, baixo uso de memória"),
            ("google/gemma-2-2b-it", "2B - Versão mais recente"),
            ("google/gemma-2-9b-it", "9B - Melhor qualidade, mais lento"),
            ("google/gemma-2-27b-it", "27B - Máxima qualidade, muito lento")
        ]
        
        for i, (model, desc) in enumerate(models, 1):
            print(f"   {i}. {model} - {desc}")
        
        print("\nEscolha o número do modelo (1-4): ", end="")
        try:
            choice_num = int(input().strip())
            if 1 <= choice_num <= len(models):
                selected_model = models[choice_num - 1][0]
            else:
                print("⚠️  Escolha inválida, usando recomendação")
                selected_model = recommended_model
        except ValueError:
            print("⚠️  Entrada inválida, usando recomendação")
            selected_model = recommended_model
    else:
        selected_model = recommended_model
    
    print(f"\n✅ Modelo selecionado: {selected_model}")
    
    # Criar configuração
    config = update_application_config(selected_model)
    
    print("\n🎯 Próximos passos:")
    print("1. Execute: python update_model_configs.py")
    print("2. Teste: python start_app.py --full")
    print("3. Verifique os logs para confirmar carregamento do modelo")
    
    print(f"\n⚠️  IMPORTANTE:")
    print(f"   - Primeira execução pode demorar (download do modelo)")
    print(f"   - Modelo será baixado para ~/.cache/huggingface/")
    print(f"   - Tamanho estimado: 2-4GB para modelos 2B, 8-16GB para 9B+")

if __name__ == "__main__":
    main()