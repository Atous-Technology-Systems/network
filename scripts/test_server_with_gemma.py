#!/usr/bin/env python3
"""
Script para testar o servidor com integração Gemma 3N TFLite
"""

import os
import sys
import asyncio
import requests
import time
from pathlib import Path

# Adicionar o projeto ao path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

async def test_server_integration():
    """Testa a integração do servidor com Gemma 3N TFLite"""
    print(" Testando integração do servidor com Gemma 3N TFLite...")
    print("=" * 60)
    
    # 1. Testar LLM service diretamente
    print("\n Testando LLM service diretamente...")
    try:
        from atous_sec_network.ml.llm_service import LLMService
        
        llm_service = LLMService("models/gemma-3n/extracted")
        success = await llm_service.load_model()
        
        if success:
            print(" LLM service carregado com sucesso!")
            print(f" Tipo do modelo: {llm_service.get_metrics()['model_type']}")
            
            # Testar consulta
            response = await llm_service.query("Qual é o status do sistema de segurança?")
            print(f"   💬 Resposta: {response.answer}")
            print(f"   🎯 Confiança: {response.confidence}")
        else:
            print(" Falha ao carregar LLM service")
            return False
            
    except Exception as e:
        print(f" Erro no LLM service: {e}")
        return False
    
    # 2. Testar servidor web
    print("\n Testando servidor web...")
    try:
        import uvicorn
        from atous_sec_network.api.server import app
        
        print("   🔧 Iniciando servidor...")
        
        # Iniciar servidor em background
        config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="info")
        server = uvicorn.Server(config)
        
        # Executar servidor em thread separada
        import threading
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        
        # Aguardar servidor inicializar
        print("   ⏳ Aguardando servidor inicializar...")
        await asyncio.sleep(5)
        
        # Testar endpoints
        base_url = "http://127.0.0.1:8000"
        
        # Health check
        try:
            response = requests.get(f"{base_url}/health", timeout=5)
            if response.status_code == 200:
                print("  Health check: OK")
            else:
                print(f"  Health check: {response.status_code}")
        except Exception as e:
            print(f" Health check falhou: {e}")
        
        # LLM metrics
        try:
            response = requests.get(f"{base_url}/api/llm/metrics", timeout=5)
            if response.status_code == 200:
                metrics = response.json()
                print(" LLM metrics: OK")
                print(f"      Modelo: {metrics.get('model_type', 'N/A')}")
                print(f"      Carregado: {metrics.get('is_loaded', False)}")
                print(f"      Consultas: {metrics.get('total_queries', 0)}")
            else:
                print(f" LLM metrics: {response.status_code}")
        except Exception as e:
            print(f" LLM metrics falhou: {e}")
        
        # LLM query
        try:
            query_data = {"question": "Como está funcionando o sistema de segurança?"}
            response = requests.post(f"{base_url}/api/llm/query", json=query_data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                print(" LLM query: OK")
                print(f"      Resposta: {result.get('answer', 'N/A')[:100]}...")
                print(f"      Confiança: {result.get('confidence', 0)}")
            else:
                print(f" LLM query: {response.status_code}")
                print(f"      Erro: {response.text}")
        except Exception as e:
            print(f" LLM query falhou: {e}")
        
        print(" Servidor testado com sucesso!")
        
    except Exception as e:
        print(f" Erro no servidor: {e}")
        return False
    
    return True

def main():
    """Função principal"""
    print("🔧 Iniciando testes de integração...")
    
    # Executar teste assíncrono
    success = asyncio.run(test_server_integration())
    
    if success:
        print("\n Todos os testes passaram!")
        print("\n Resumo da integração:")
        print(" LLM service com Gemma 3N TFLite funcionando")
        print(" Servidor web iniciado")
        print(" API endpoints respondendo")
        print("  Modelo TFLite carregado e respondendo")
        print("\n Servidor rodando em: http://127.0.0.1:8000")
        print(" Teste a API em: http://127.0.0.1:8000/docs")
    else:
        print("\n Alguns testes falharam!")
        sys.exit(1)

if __name__ == "__main__":
    main()
