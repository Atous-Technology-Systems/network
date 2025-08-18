#!/usr/bin/env python3
"""
Script para testar funcionalidades específicas do sistema
"""

import requests
import json

def test_specific_features():
    """Testa funcionalidades específicas"""
    base_url = "http://127.0.0.1:8000"
    
    print("🔍 TESTANDO FUNCIONALIDADES ESPECÍFICAS")
    print("=" * 50)
    
    # Teste 1: Root endpoint
    print("\n1. Root endpoint:")
    try:
        r = requests.get(base_url + "/")
        print(f"   Status: {r.status_code}")
        print(f"   Content-Type: {r.headers.get('content-type', 'N/A')}")
        if r.status_code == 200:
            print(f"   Content Length: {len(r.text)} chars")
    except Exception as e:
        print(f"   Erro: {e}")
    
    # Teste 2: Discovery com parâmetros
    print("\n2. Discovery com parâmetros:")
    try:
        r = requests.get(base_url + "/v1/discovery/services?name=test")
        print(f"   Status: {r.status_code}")
        if r.status_code == 200:
            print(f"   Response: {r.text[:100]}...")
        else:
            print(f"   Error: {r.text}")
    except Exception as e:
        print(f"   Erro: {e}")
    
    # Teste 3: LLM com diferentes tipos de pergunta
    print("\n3. LLM com diferentes tipos de pergunta:")
    questions = [
        "Qual é a versão do sistema?",
        "Como funciona o sistema ABISS?",
        "Status dos sistemas de rede"
    ]
    
    for i, question in enumerate(questions, 1):
        try:
            data = {"question": question}
            r = requests.post(base_url + "/api/llm/query", json=data)
            print(f"   Pergunta {i}: {r.status_code}")
            if r.status_code == 200:
                response_data = r.json()
                print(f"     Resposta: {response_data.get('answer', 'N/A')[:50]}...")
            else:
                print(f"     Erro: {r.text}")
        except Exception as e:
            print(f"   Erro na pergunta {i}: {e}")
    
    # Teste 4: Security endpoints específicos
    print("\n4. Security endpoints específicos:")
    security_endpoints = [
        "/api/security/abiss/status",
        "/api/security/nnis/status",
        "/api/security/abiss/config",
        "/api/security/nnis/config"
    ]
    
    for endpoint in security_endpoints:
        try:
            r = requests.get(base_url + endpoint)
            print(f"   {endpoint}: {r.status_code}")
        except Exception as e:
            print(f"   {endpoint}: Erro - {e}")
    
    # Teste 5: Admin com dados
    print("\n5. Admin com dados:")
    try:
        r = requests.get(base_url + "/v1/admin/overview")
        if r.status_code == 200:
            data = r.json()
            print(f"   Status: {r.status_code}")
            print(f"   Sistemas ativos: {data.get('active_systems', 'N/A')}")
            print(f"   Total eventos: {data.get('total_events', 'N/A')}")
        else:
            print(f"   Status: {r.status_code}")
            print(f"   Erro: {r.text}")
    except Exception as e:
        print(f"   Erro: {e}")

if __name__ == "__main__":
    test_specific_features()
