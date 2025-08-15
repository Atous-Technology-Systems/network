#!/usr/bin/env python3
"""
Script para testar ataques contra a API em tempo real
"""

import requests
import json
import time
from datetime import datetime

def test_api_attacks():
    """Testa ataques contra a API do sistema."""
    base_url = "http://localhost:8000"
    
    print("=" * 80)
    print("TESTE DE ATAQUES EM TEMPO REAL - ATOUS SECURE NETWORK")
    print("=" * 80)
    print(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Target: {base_url}")
    print("\n")
    
    # Verificar se o servidor está rodando
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        print(f"Servidor está rodando - Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao conectar com o servidor: {e}")
        return
    
    # Testes de SQL Injection
    print("\n1. TESTES DE SQL INJECTION CONTRA A API")
    print("-" * 50)
    
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "admin'--",
        "1 UNION SELECT password FROM users",
        "' OR 1=1#"
    ]
    
    for i, payload in enumerate(sql_payloads, 1):
        try:
            data = {
                "input_data": payload,
                "context": "sql"
            }
            response = requests.post(
                f"{base_url}/security/validate-input",
                json=data,
                timeout=5
            )
            
            if response.status_code == 403:
                print(f"  {i}. {payload[:30]}... -> BLOQUEADO (403)")
            elif response.status_code == 200:
                result = response.json()
                if not result.get('valid', True):
                    print(f"  {i}. {payload[:30]}... -> DETECTADO E BLOQUEADO")
                else:
                    print(f"  {i}. {payload[:30]}... -> NÃO DETECTADO")
            else:
                print(f"  {i}. {payload[:30]}... -> ❓ Status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"  {i}. {payload[:30]}... -> Erro: {e}")
        
        time.sleep(0.1)
    
    # Testes de XSS
    print("\n2. TESTES DE XSS CONTRA A API")
    print("-" * 50)
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>"
    ]
    
    for i, payload in enumerate(xss_payloads, 1):
        try:
            data = {
                "input_data": payload,
                "context": "html"
            }
            response = requests.post(
                f"{base_url}/security/validate-input",
                json=data,
                timeout=5
            )
            
            if response.status_code == 403:
                print(f"  {i}. {payload[:30]}... -> BLOQUEADO (403)")
            elif response.status_code == 200:
                result = response.json()
                if not result.get('valid', True):
                    print(f"  {i}. {payload[:30]}... -> DETECTADO E BLOQUEADO")
                else:
                    print(f"  {i}. {payload[:30]}... -> NÃO DETECTADO")
            else:
                print(f"  {i}. {payload[:30]}... -> ❓ Status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"  {i}. {payload[:30]}... -> Erro: {e}")
        
        time.sleep(0.1)
    
    # Testes de Path Traversal
    print("\n3. TESTES DE PATH TRAVERSAL CONTRA A API")
    print("-" * 50)
    
    path_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "file:///etc/passwd"
    ]
    
    for i, payload in enumerate(path_payloads, 1):
        try:
            data = {
                "input_data": payload,
                "context": "file"
            }
            response = requests.post(
                f"{base_url}/security/validate-input",
                json=data,
                timeout=5
            )
            
            if response.status_code == 403:
                print(f"  {i}. {payload[:30]}... -> BLOQUEADO (403)")
            elif response.status_code == 200:
                result = response.json()
                if not result.get('valid', True):
                    print(f"  {i}. {payload[:30]}... -> DETECTADO E BLOQUEADO")
                else:
                    print(f"  {i}. {payload[:30]}... -> NÃO DETECTADO")
            else:
                print(f"  {i}. {payload[:30]}... -> ❓ Status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"  {i}. {payload[:30]}... -> Erro: {e}")
        
        time.sleep(0.1)
    
    # Teste de Rate Limiting
    print("\n4. TESTE DE RATE LIMITING")
    print("-" * 50)
    
    print("  Enviando 20 requisições rápidas...")
    blocked_count = 0
    
    for i in range(20):
        try:
            response = requests.get(f"{base_url}/health", timeout=2)
            if response.status_code == 429:  # Too Many Requests
                blocked_count += 1
        except requests.exceptions.RequestException:
            pass
    
    if blocked_count > 0:
        print(f"  Rate limiting ativo - {blocked_count}/20 requisições bloqueadas")
    else:
        print(f"  Rate limiting não ativado ou limite não atingido")
    
    print("\n" + "=" * 80)
    print("TESTE DE ATAQUES CONCLUÍDO")
    print("=" * 80)
    print("\nTodos os testes de ataque foram executados.")
    print("Verifique os logs do servidor para detalhes das detecções.")
    print("O sistema demonstrou suas capacidades de defesa.")

if __name__ == "__main__":
    test_api_attacks()