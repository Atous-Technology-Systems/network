#!/usr/bin/env python3
"""
Teste dos Endpoints da API - ATous Secure Network
"""

import requests
import json
import time
from datetime import datetime

def test_api_endpoints():
    print("="*80)
    print("TESTE DOS ENDPOINTS DA API - ATOUS SECURE NETWORK")
    print("="*80)
    
    base_url = "http://localhost:8000"
    results = []
    
    # Lista de endpoints para testar
    endpoints = [
        {
            "name": "Health Check",
            "url": f"{base_url}/health",
            "method": "GET"
        },
        {
            "name": "Security Status",
            "url": f"{base_url}/api/security/status",
            "method": "GET"
        },
        {
            "name": "Root Endpoint",
            "url": f"{base_url}/",
            "method": "GET"
        },
        {
            "name": "Docs",
            "url": f"{base_url}/docs",
            "method": "GET"
        }
    ]
    
    print(f"\nTestando {len(endpoints)} endpoints...\n")
    
    for i, endpoint in enumerate(endpoints, 1):
        print(f"{i}. TESTANDO {endpoint['name'].upper()}")
        print("-" * 50)
        
        try:
            start_time = time.time()
            response = requests.get(endpoint['url'], timeout=10)
            response_time = time.time() - start_time
            
            status = "SUCESSO" if response.status_code < 400 else "ERRO"
            
            result = {
                "endpoint": endpoint['name'],
                "url": endpoint['url'],
                "status_code": response.status_code,
                "response_time": round(response_time * 1000, 2),
                "success": response.status_code < 400,
                "content_length": len(response.text),
                "timestamp": datetime.now().isoformat()
            }
            
            print(f"   URL: {endpoint['url']}")
            print(f"   Status: {response.status_code} {status}")
            print(f"   Tempo de resposta: {result['response_time']}ms")
            print(f"   Tamanho da resposta: {result['content_length']} bytes")
            
            # Mostrar parte do conteúdo se for pequeno
            if len(response.text) < 200:
                print(f"   Conteúdo: {response.text[:100]}...")
            
            results.append(result)
            
        except requests.exceptions.ConnectionError:
            print(f"   ERRO: Não foi possível conectar ao servidor")
            print(f"   URL: {endpoint['url']}")
            print(f"   Motivo: Servidor não está rodando ou não está acessível")
            
            result = {
                "endpoint": endpoint['name'],
                "url": endpoint['url'],
                "status_code": 0,
                "response_time": 0,
                "success": False,
                "error": "Connection refused",
                "timestamp": datetime.now().isoformat()
            }
            results.append(result)
            
        except requests.exceptions.Timeout:
            print(f"   ERRO: Timeout na requisição")
            result = {
                "endpoint": endpoint['name'],
                "url": endpoint['url'],
                "status_code": 0,
                "response_time": 10000,
                "success": False,
                "error": "Timeout",
                "timestamp": datetime.now().isoformat()
            }
            results.append(result)
            
        except Exception as e:
            print(f"   ERRO: {str(e)}")
            result = {
                "endpoint": endpoint['name'],
                "url": endpoint['url'],
                "status_code": 0,
                "response_time": 0,
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
            results.append(result)
        
        print()
    
    # Resumo dos resultados
    print("="*80)
    print("RESUMO DOS TESTES DE ENDPOINTS")
    print("="*80)
    
    successful = sum(1 for r in results if r['success'])
    total = len(results)
    success_rate = (successful / total) * 100 if total > 0 else 0
    
    print(f"Total de endpoints testados: {total}")
    print(f"Endpoints funcionando: {successful}")
    print(f"Endpoints com erro: {total - successful}")
    print(f"Taxa de sucesso: {success_rate:.1f}%")
    
    if success_rate >= 75:
        print("\n🟢 STATUS DA API: FUNCIONANDO")
    elif success_rate >= 50:
        print("\n🟡 STATUS DA API: PARCIALMENTE FUNCIONANDO")
    else:
        print("\n🔴 STATUS DA API: COM PROBLEMAS")
    
    # Salvar relatório
    report = {
        "test_type": "API Endpoints Test",
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_endpoints": total,
            "successful_endpoints": successful,
            "failed_endpoints": total - successful,
            "success_rate": success_rate
        },
        "results": results
    }
    
    with open('api_endpoints_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\nRelatório detalhado salvo em: api_endpoints_report.json")
    print("="*80)

if __name__ == "__main__":
    test_api_endpoints()