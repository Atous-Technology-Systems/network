#!/usr/bin/env python3
"""
Script de teste completo para ATous Secure Network
Testa todos os endpoints e funcionalidades do sistema
"""

import requests
import json
import time
from datetime import datetime

def test_endpoint(url, method="GET", data=None, headers=None):
    """Testa um endpoint específico"""
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, json=data, headers=headers, timeout=10)
        else:
            return False, f"Método {method} não suportado"
        
        return response.status_code, response.text[:200] + "..." if len(response.text) > 200 else response.text
    except Exception as e:
        return None, str(e)

def main():
    """Função principal de teste"""
    base_url = "http://127.0.0.1:8000"
    
    print("=" * 60)
    print("🧪 TESTE COMPLETO DO SISTEMA ATOUS SECURE NETWORK")
    print("=" * 60)
    print(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Base URL: {base_url}")
    print()
    
    # Teste 1: Endpoints básicos
    print("📋 TESTANDO ENDPOINTS BÁSICOS")
    print("-" * 40)
    
    basic_endpoints = [
        ("/", "GET"),
        ("/health", "GET"),
        ("/docs", "GET"),
        ("/openapi.json", "GET"),
        ("/api/info", "GET")
    ]
    
    for endpoint, method in basic_endpoints:
        url = base_url + endpoint
        status, response = test_endpoint(url, method)
        print(f"{endpoint:20} [{method:4}] -> {status if status else 'ERROR'}")
        if status and status != 200:
            print(f"  ⚠️  Resposta: {response}")
    
    print()
    
    # Teste 2: Endpoints de segurança
    print("🔒 TESTANDO ENDPOINTS DE SEGURANÇA")
    print("-" * 40)
    
    security_endpoints = [
        ("/api/security/status", "GET"),
        ("/api/security/config", "GET"),
        ("/api/security/abiss/status", "GET"),
        ("/api/security/nnis/status", "GET")
    ]
    
    for endpoint, method in security_endpoints:
        url = base_url + endpoint
        status, response = test_endpoint(url, method)
        print(f"{endpoint:30} [{method:4}] -> {status if status else 'ERROR'}")
        if status and status != 200:
            print(f"  ⚠️  Resposta: {response}")
    
    print()
    
    # Teste 3: Endpoints LLM
    print("🤖 TESTANDO ENDPOINTS LLM")
    print("-" * 40)
    
    llm_endpoints = [
        ("/api/llm/status", "GET"),
        ("/api/llm/metrics", "GET")
    ]
    
    for endpoint, method in llm_endpoints:
        url = base_url + endpoint
        status, response = test_endpoint(url, method)
        print(f"{endpoint:25} [{method:4}] -> {status if status else 'ERROR'}")
        if status and status != 200:
            print(f"  ⚠️  Resposta: {response}")
    
    # Teste 4: LLM Query
    print("\n🔍 TESTANDO LLM QUERY")
    print("-" * 40)
    
    query_data = {"question": "Como está o sistema de segurança?"}
    url = base_url + "/api/llm/query"
    status, response = test_endpoint(url, "POST", query_data)
    print(f"LLM Query [POST] -> {status if status else 'ERROR'}")
    if status and status != 200:
        print(f"  ⚠️  Resposta: {response}")
    
    print()
    
    # Teste 5: Endpoints de rede
    print("🌐 TESTANDO ENDPOINTS DE REDE")
    print("-" * 40)
    
    network_endpoints = [
        ("/v1/discovery/services", "GET"),
        ("/v1/relay/status", "GET"),
        ("/api/network/lora/status", "GET"),
        ("/api/network/p2p/status", "GET")
    ]
    
    for endpoint, method in network_endpoints:
        url = base_url + endpoint
        status, response = test_endpoint(url, method)
        print(f"{endpoint:30} [{method:4}] -> {status if status else 'ERROR'}")
        if status and status != 200:
            print(f"  ⚠️  Resposta: {response}")
    
    print()
    
    # Teste 6: Endpoints admin
    print("👑 TESTANDO ENDPOINTS ADMIN")
    print("-" * 40)
    
    admin_endpoints = [
        ("/v1/admin/overview", "GET"),
        ("/v1/admin/events", "GET")
    ]
    
    for endpoint, method in admin_endpoints:
        url = base_url + endpoint
        status, response = test_endpoint(url, method)
        print(f"{endpoint:25} [{method:4}] -> {status if status else 'ERROR'}")
        if status and status != 200:
            print(f"  ⚠️  Resposta: {response}")
    
    print()
    
    # Teste 7: Status geral do sistema
    print("📊 STATUS GERAL DO SISTEMA")
    print("-" * 40)
    
    try:
        health_response = requests.get(base_url + "/health", timeout=10)
        if health_response.status_code == 200:
            health_data = health_response.json()
            print(f"Status Geral: {health_data['status']}")
            print("Sistemas:")
            for system, info in health_data['systems'].items():
                print(f"  - {system}: {info['status']}")
            print(f"Uptime: {health_data['metrics']['uptime_seconds']:.1f}s")
            print(f"Memória: {health_data['metrics']['memory_usage_mb']:.1f}MB")
        else:
            print(f"❌ Erro ao obter status: {health_response.status_code}")
    except Exception as e:
        print(f"❌ Erro ao obter status: {e}")
    
    print()
    print("=" * 60)
    print("✅ TESTE COMPLETO FINALIZADO")
    print("=" * 60)

if __name__ == "__main__":
    main()
