#!/usr/bin/env python3
"""
Script para testar todos os endpoints problemáticos
"""
import requests
import json

def test_endpoints():
    """Testa todos os endpoints problemáticos"""
    base_url = "http://127.0.0.1:8000"
    
    print("🧪 Testando endpoints problemáticos...")
    print("=" * 50)
    
    # 1. Testar health check
    print("\n1️⃣ Testando health check...")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Health check funcionando")
        else:
            print(f"   ❌ Health check falhou: {response.text}")
    except Exception as e:
        print(f"   ❌ Health check erro: {e}")
    
    # 2. Testar WebSocket endpoint
    print("\n2️⃣ Testando WebSocket endpoint...")
    try:
        response = requests.get(f"{base_url}/api/llm/ws", timeout=5)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ WebSocket funcionando")
        elif response.status_code == 404:
            print("   ❌ WebSocket ainda retornando 404")
        else:
            print(f"   ⚠️  WebSocket status inesperado: {response.text}")
    except Exception as e:
        print(f"   ❌ WebSocket erro: {e}")
    
    # 3. Testar endpoint de métricas LLM
    print("\n3️⃣ Testando endpoint de métricas LLM...")
    try:
        response = requests.get(f"{base_url}/api/llm/metrics", timeout=5)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Métricas LLM funcionando")
        elif response.status_code == 404:
            print("   ❌ Métricas LLM ainda retornando 404")
        else:
            print(f"   ⚠️  Métricas LLM status inesperado: {response.text}")
    except Exception as e:
        print(f"   ❌ Métricas LLM erro: {e}")
    
    # 4. Testar endpoint de consulta LLM
    print("\n4️⃣ Testando endpoint de consulta LLM...")
    try:
        payload = {
            "question": "Como está o sistema?",
            "include_system_context": True
        }
        response = requests.post(f"{base_url}/api/llm/query", json=payload, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Consulta LLM funcionando")
        else:
            print(f"   ❌ Consulta LLM falhou: {response.text}")
    except Exception as e:
        print(f"   ❌ Consulta LLM erro: {e}")
    
    # 5. Testar endpoint de registro (deve dar erro de validação, não 500)
    print("\n5️⃣ Testando endpoint de registro...")
    try:
        payload = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "TestPass123!",
            "roles": ["admin"]  # Role válido
        }
        response = requests.post(f"{base_url}/auth/register", json=payload, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 422:
            print("   ✅ Registro retornando erro de validação (esperado)")
        elif response.status_code == 500:
            print("   ❌ Registro retornando erro interno (problema)")
        else:
            print(f"   ⚠️  Registro status inesperado: {response.text}")
    except Exception as e:
        print(f"   ❌ Registro erro: {e}")

def main():
    """Função principal"""
    test_endpoints()

if __name__ == "__main__":
    main()
