#!/usr/bin/env python3
"""
Script para verificar a documentação da API
"""
import requests
import json

def check_api_docs():
    """Verifica a documentação da API"""
    base_url = "http://127.0.0.1:8000"
    
    print("🔍 Verificando documentação da API...")
    print("=" * 50)
    
    # 1. Verificar OpenAPI schema
    print("\n1️⃣ Verificando OpenAPI schema...")
    try:
        response = requests.get(f"{base_url}/openapi.json", timeout=10)
        if response.status_code == 200:
            schema = response.json()
            
            # Listar todos os paths
            print("   📋 Endpoints disponíveis:")
            for path, methods in schema.get("paths", {}).items():
                for method, details in methods.items():
                    if method.upper() in ["GET", "POST", "PUT", "DELETE", "WEBSOCKET"]:
                        tags = details.get("tags", ["sem tag"])
                        print(f"      {method.upper():<10} {path:<30} [{', '.join(tags)}]")
            
            # Verificar se há WebSocket endpoints
            websocket_endpoints = []
            for path, methods in schema.get("paths", {}).items():
                if "websocket" in methods:
                    websocket_endpoints.append(path)
            
            if websocket_endpoints:
                print(f"\n   🔌 WebSocket endpoints encontrados: {websocket_endpoints}")
            else:
                print("\n   ❌ Nenhum endpoint WebSocket encontrado")
                
        else:
            print(f"   ❌ Falha ao obter schema: {response.status_code}")
            
    except Exception as e:
        print(f"   ❌ Erro ao verificar schema: {e}")
    
    # 2. Verificar se o endpoint LLM está funcionando
    print("\n2️⃣ Testando endpoint LLM...")
    try:
        response = requests.get(f"{base_url}/api/llm/status", timeout=5)
        print(f"   Status LLM: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Endpoint LLM funcionando")
        else:
            print(f"   ❌ Endpoint LLM falhou: {response.text}")
    except Exception as e:
        print(f"   ❌ Erro no endpoint LLM: {e}")
    
    # 3. Verificar se o endpoint de métricas está funcionando
    print("\n3️⃣ Testando endpoint de métricas...")
    try:
        response = requests.get(f"{base_url}/api/llm/metrics", timeout=5)
        print(f"   Status métricas: {response.status_code}")
        if response.status_code == 200:
            print("   ✅ Endpoint de métricas funcionando")
        else:
            print(f"   ❌ Endpoint de métricas falhou: {response.text}")
    except Exception as e:
        print(f"   ❌ Erro no endpoint de métricas: {e}")

def main():
    """Função principal"""
    check_api_docs()

if __name__ == "__main__":
    main()
