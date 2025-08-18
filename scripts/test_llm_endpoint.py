#!/usr/bin/env python3
"""
Script para testar o endpoint LLM via HTTP
"""

import requests
import json
import time
from datetime import datetime

def test_llm_endpoint():
    """Testa o endpoint LLM via HTTP"""
    base_url = "http://127.0.0.1:8000"
    
    print("🧪 Testando endpoint LLM via HTTP...")
    print("=" * 50)
    
    # 1. Testar health check
    print("\n1️⃣ Testando health check...")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("   ✅ Health check: OK")
            health_data = response.json()
            print(f"      Status: {health_data.get('status', 'N/A')}")
        else:
            print(f"   ❌ Health check: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Health check falhou: {e}")
        return False
    
    # 2. Testar status do LLM
    print("\n2️⃣ Testando status do LLM...")
    try:
        response = requests.get(f"{base_url}/api/llm/status", timeout=5)
        if response.status_code == 200:
            print("   ✅ Status LLM: OK")
            status_data = response.json()
            print(f"      Modelo carregado: {status_data.get('is_loaded', False)}")
            print(f"      Tipo: {status_data.get('model_type', 'N/A')}")
        else:
            print(f"   ❌ Status LLM: {response.status_code}")
            print(f"      Erro: {response.text}")
    except Exception as e:
        print(f"   ❌ Status LLM falhou: {e}")
    
    # 3. Testar métricas do LLM
    print("\n3️⃣ Testando métricas do LLM...")
    try:
        response = requests.get(f"{base_url}/api/llm/metrics", timeout=5)
        if response.status_code == 200:
            print("   ✅ Métricas LLM: OK")
            metrics_data = response.json()
            print(f"      Consultas: {metrics_data.get('total_queries', 0)}")
            print(f"      Cache: {metrics_data.get('cache_size', 0)}")
            print(f"      Tempo médio: {metrics_data.get('average_response_time', 0):.4f}s")
        else:
            print(f"   ❌ Métricas LLM: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Métricas LLM falhou: {e}")
    
    # 4. Testar consulta ao LLM
    print("\n4️⃣ Testando consulta ao LLM...")
    
    test_questions = [
        "Como está o sistema de segurança?",
        "Há alguma ameaça detectada?",
        "Quantos usuários estão ativos?",
        "Qual é o status do ABISS?",
        "Como funciona o NNIS?"
    ]
    
    for i, question in enumerate(test_questions, 1):
        print(f"\n   {i}. Testando: {question}")
        
        try:
            # Preparar payload
            payload = {
                "question": question,
                "context": {},
                "include_system_context": True
            }
            
            # Fazer requisição
            response = requests.post(
                f"{base_url}/api/llm/query",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                print("      ✅ Sucesso!")
                result = response.json()
                print(f"      💬 Resposta: {result.get('answer', 'N/A')[:100]}...")
                print(f"      🎯 Confiança: {result.get('confidence', 0):.2f}")
                print(f"      📍 Fontes: {', '.join(result.get('sources', []))}")
                print(f"      ⏱️  Tempo: {result.get('processing_time', 0):.4f}s")
            else:
                print(f"      ❌ Erro {response.status_code}: {response.text}")
                
        except Exception as e:
            print(f"      ❌ Falha: {e}")
        
        # Aguardar um pouco entre as consultas
        time.sleep(1)
    
    # 5. Testar WebSocket (se disponível)
    print("\n5️⃣ Testando WebSocket...")
    try:
        response = requests.get(f"{base_url}/api/llm/ws", timeout=5)
        if response.status_code == 200:
            print("   ✅ WebSocket disponível")
        else:
            print(f"   ℹ️  WebSocket: {response.status_code}")
    except Exception as e:
        print(f"   ℹ️  WebSocket não testado: {e}")
    
    print("\n🎉 Teste do endpoint LLM concluído!")
    print(f"\n📝 URLs para testar no Postman:")
    print(f"   Health: GET {base_url}/health")
    print(f"   Status: GET {base_url}/api/llm/status")
    print(f"   Métricas: GET {base_url}/api/llm/metrics")
    print(f"   Consulta: POST {base_url}/api/llm/query")
    print(f"   WebSocket: GET {base_url}/api/llm/ws")
    
    return True

def main():
    """Função principal"""
    print("🚀 Iniciando teste do endpoint LLM...")
    
    success = test_llm_endpoint()
    
    if success:
        print("\n🎉 Teste concluído!")
    else:
        print("\n❌ Teste falhou!")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
