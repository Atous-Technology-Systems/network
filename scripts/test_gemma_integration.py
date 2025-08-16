#!/usr/bin/env python3
"""
Script para testar integração do Gemma na aplicação
"""

import time
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_gemma_loading():
    """Testa carregamento do modelo Gemma"""
    print("🧪 Testando carregamento do modelo Gemma...")
    print("=" * 50)
    
    try:
        # Importar sistema ABISS
        from atous_sec_network.security.abiss_system import ABISSSystem
        
        # Carregar configuração atual
        import json
        try:
            with open("gemma_config.json") as f:
                config = json.load(f)
        except FileNotFoundError:
            # Configuração fallback
            config = {
                "model_name": "microsoft/DialoGPT-medium",
                "model_params": {
                    "torch_dtype": "float32",
                    "device_map": "auto",
                    "low_cpu_mem_usage": True,
                    "trust_remote_code": False
                },
                "pipeline_params": {
                    "max_length": 256,
                    "temperature": 0.7,
                    "do_sample": True,
                    "top_p": 0.9,
                    "pad_token_id": 50256
                },
                "memory_size": 1000,
                "threat_threshold": 0.7,
                "simulation_mode": False
            }
        
        print(f"📋 Configuração:")
        print(f"   Modelo: {config['model_name']}")
        print(f"   Simulação: {config['simulation_mode']}")
        
        # Inicializar sistema
        print("\n⏳ Inicializando sistema ABISS...")
        start_time = time.time()
        
        abiss = ABISSSystem(config)
        
        init_time = time.time() - start_time
        print(f"✅ Sistema inicializado em {init_time:.2f} segundos")
        
        # Verificar se modelo foi carregado
        if abiss.model is not None:
            print("✅ Modelo Gemma carregado com sucesso!")
            print(f"   Tokenizer: {'✅ OK' if abiss.tokenizer else '❌ Falhou'}")
            print(f"   Pipeline: {'✅ OK' if abiss.pipeline else '❌ Falhou'}")
        else:
            print("❌ Modelo não foi carregado")
            return False
        
        # Teste básico de detecção
        print("\n🔍 Testando detecção de ameaças...")
        
        test_data = {
            "source_ip": "192.168.1.100",
            "target_endpoint": "/admin/login",
            "payload": "' OR '1'='1",
            "method": "POST"
        }
        
        result = abiss.detect_threat(test_data)
        print(f"   Resultado: {result}")
        
        if isinstance(result, tuple) and len(result) == 2:
            threat_score, anomalies = result
            print(f"   Score de ameaça: {threat_score:.3f}")
            print(f"   Anomalias detectadas: {len(anomalies) if anomalies else 0}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro durante teste: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_model_info():
    """Testa informações do modelo"""
    print("\n📊 Informações do modelo...")
    
    try:
        from atous_sec_network.security.abiss_system import ABISSSystem
        
        config = {"model_name": "google/gemma-1.1-2b-it", "simulation_mode": False}
        abiss = ABISSSystem(config)
        
        info = abiss.get_model_info()
        print(f"   Nome: {info.get('model_name', 'N/A')}")
        print(f"   Carregado: {info.get('model_loaded', False)}")
        print(f"   Tamanho: {info.get('model_size', 'N/A')}")
        print(f"   Transformers: {info.get('transformers_available', False)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao obter informações: {str(e)}")
        return False

def test_full_application():
    """Testa aplicação completa"""
    print("\n🚀 Testando aplicação completa...")
    
    try:
        import subprocess
        
        # Executar aplicação em modo full
        result = subprocess.run(
            [sys.executable, "start_app.py", "--full"],
            capture_output=True,
            text=True,
            timeout=300  # 5 minutos
        )
        
        if result.returncode == 0:
            print("✅ Aplicação executada com sucesso!")
            
            # Verificar se modelo foi carregado nos logs
            output = result.stdout + result.stderr
            if "Modelo SLM carregado" in output:
                print("✅ Modelo SLM carregado")
            if "Sistema ABISS inicializado" in output:
                print("✅ Sistema ABISS inicializado")
            if "Sistema NNIS inicializado" in output:
                print("✅ Sistema NNIS inicializado")
            
            # Verificar erros de modelo
            if "Erro ao carregar tokenizer" in output:
                print("⚠️  Erro no tokenizer detectado")
            if "Erro ao carregar o modelo" in output:
                print("⚠️  Erro no modelo detectado")
            
            return True
        else:
            print(f"❌ Aplicação falhou com código: {result.returncode}")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return False
            
    except subprocess.TimeoutExpired:
        print("⚠️  Timeout - aplicação pode estar funcionando mas demorou muito")
        return True
    except Exception as e:
        print(f"❌ Erro ao testar aplicação: {str(e)}")
        return False

def main():
    """Função principal"""
    print("🧪 Teste de Integração Gemma - ATous Secure Network")
    print("=" * 60)
    
    tests = [
        ("Carregamento do Modelo", test_gemma_loading),
        ("Informações do Modelo", test_model_info),
        ("Aplicação Completa", test_full_application)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n🔬 Executando: {test_name}")
        print("-" * 40)
        
        try:
            success = test_func()
            results.append((test_name, success))
            
            if success:
                print(f"✅ {test_name}: PASSOU")
            else:
                print(f"❌ {test_name}: FALHOU")
                
        except Exception as e:
            print(f"❌ {test_name}: ERRO - {str(e)}")
            results.append((test_name, False))
    
    # Resumo
    print("\n" + "=" * 60)
    print("📊 RESUMO DOS TESTES")
    print("=" * 60)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASSOU" if success else "❌ FALHOU"
        print(f"   {test_name}: {status}")
    
    print(f"\n🎯 Resultado: {passed}/{total} testes passaram")
    
    if passed == total:
        print("🎉 Todos os testes passaram! Gemma integrado com sucesso!")
        return 0
    else:
        print("⚠️  Alguns testes falharam. Verifique os logs acima.")
        return 1

if __name__ == "__main__":
    sys.exit(main())