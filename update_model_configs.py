#!/usr/bin/env python3
"""
Script para atualizar configurações de modelo na aplicação
"""

import json
from pathlib import Path

def load_gemma_config():
    """Carrega configuração do Gemma"""
    config_file = Path("gemma_config.json")
    if not config_file.exists():
        print("❌ Arquivo gemma_config.json não encontrado!")
        print("   Execute primeiro: python configure_gemma.py")
        return None
    
    with open(config_file) as f:
        return json.load(f)

def update_main_module():
    """Atualiza o módulo principal com nova configuração"""
    main_file = Path("atous_sec_network/__main__.py")
    
    if not main_file.exists():
        print("❌ Arquivo __main__.py não encontrado!")
        return False
    
    # Ler arquivo atual
    with open(main_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Carregar configuração
    config = load_gemma_config()
    if not config:
        return False
    
    model_name = config["model_name"]
    
    # Substituir configuração ABISS
    old_abiss_config = '''abiss_config = {
            "model_name": "google/gemma-3n-2b",
            "memory_size": 1000,
            "threat_threshold": 0.7,
            "simulation_mode": True
        }'''
    
    new_abiss_config = f'''abiss_config = {{
            "model_name": "{model_name}",
            "model_params": {config["model_params"]},
            "pipeline_params": {config["pipeline_params"]},
            "memory_size": {config["memory_size"]},
            "threat_threshold": {config["threat_threshold"]},
            "simulation_mode": {str(config["simulation_mode"]).lower()}
        }}'''
    
    # Substituir configuração NNIS
    old_nnis_config = '''nnis_config = {
            "simulation_mode": True,
            "memory_size": 1000
        }'''
    
    new_nnis_config = f'''nnis_config = {{
            "model_name": "{model_name}",
            "model_params": {config["model_params"]},
            "simulation_mode": {str(config["simulation_mode"]).lower()},
            "memory_size": {config["memory_size"]}
        }}'''
    
    # Aplicar substituições
    content = content.replace(old_abiss_config, new_abiss_config)
    content = content.replace(old_nnis_config, new_nnis_config)
    
    # Salvar arquivo atualizado
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✅ Arquivo {main_file} atualizado com modelo: {model_name}")
    return True

def create_init_file():
    """Cria arquivo __init__.py no diretório config se não existir"""
    config_dir = Path("atous_sec_network/config")
    config_dir.mkdir(exist_ok=True)
    
    init_file = config_dir / "__init__.py"
    if not init_file.exists():
        with open(init_file, 'w') as f:
            f.write('"""Configurações da aplicação ATous Secure Network"""\n')
        print(f"✅ Criado: {init_file}")

def update_nnis_system():
    """Atualiza sistema NNIS para aceitar model_name na configuração"""
    nnis_file = Path("atous_sec_network/security/nnis_system.py")
    
    if not nnis_file.exists():
        print("⚠️  Arquivo nnis_system.py não encontrado")
        return False
    
    # Ler arquivo
    with open(nnis_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Verificar se já tem model_name no __init__
    if 'self.model_name = config.get("model_name"' not in content:
        # Encontrar a linha onde adicionar model_name
        init_pattern = 'def __init__(self, config: Dict[str, Any]):'
        if init_pattern in content:
            # Adicionar model_name após a configuração
            old_line = 'self.config = config'
            new_lines = '''self.config = config
        self.model_name = config.get("model_name", "google/gemma-1.1-2b-it")'''
            
            content = content.replace(old_line, new_lines)
            
            # Salvar arquivo
            with open(nnis_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"✅ Arquivo {nnis_file} atualizado para suportar model_name")
            return True
    
    print(f"✅ Arquivo {nnis_file} já está atualizado")
    return True

def main():
    """Função principal"""
    print("🔧 Atualizando configurações de modelo...")
    print("=" * 50)
    
    # Carregar configuração
    config = load_gemma_config()
    if not config:
        return 1
    
    print(f"📋 Modelo configurado: {config['model_name']}")
    print(f"🎯 Modo simulação: {config['simulation_mode']}")
    
    # Criar estrutura de diretórios
    create_init_file()
    
    # Atualizar arquivos
    success = True
    success &= update_main_module()
    success &= update_nnis_system()
    
    if success:
        print("\n✅ Todas as configurações foram atualizadas!")
        print("\n🚀 Próximos passos:")
        print("1. Teste a configuração: python start_app.py --full")
        print("2. Verifique os logs para confirmar carregamento do modelo")
        print("3. Se houver erro, execute: python start_app.py --debug")
        
        print("\n📊 Informações do modelo:")
        print(f"   Nome: {config['model_name']}")
        print(f"   Parâmetros: {config.get('model_params', {})}")
        print(f"   Pipeline: {config.get('pipeline_params', {})}")
        
        return 0
    else:
        print("\n❌ Algumas atualizações falharam!")
        return 1

if __name__ == "__main__":
    exit(main())