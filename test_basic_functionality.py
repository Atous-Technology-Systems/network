#!/usr/bin/env python3
"""
Teste Básico de Funcionalidades ATous Secure Network
"""

import requests
import json
import time
from datetime import datetime

def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def test_basic_endpoints():
    """Testa endpoints básicos da API"""
    log("🌐 === TESTE DE ENDPOINTS BÁSICOS ===")
    
    base_url = "http://127.0.0.1:8000"
    endpoints = [
        ("/", "Página Principal"),
        ("/health", "Health Check"),
        ("/docs", "Documentação Swagger"),
        ("/openapi.json", "OpenAPI Schema")
    ]
    
    results = []
    
    for endpoint, description in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            status = "✅ SUCESSO" if response.status_code == 200 else f"⚠️ STATUS {response.status_code}"
            log(f"{status} - {description}: {endpoint}")
            results.append({
                "endpoint": endpoint,
                "description": description,
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "response_time": response.elapsed.total_seconds()
            })
        except Exception as e:
            log(f"❌ ERRO - {description}: {str(e)}")
            results.append({
                "endpoint": endpoint,
                "description": description,
                "error": str(e),
                "success": False
            })
    
    return results

def test_crypto_utils():
    """Testa utilitários de criptografia básicos"""
    log("🔐 === TESTE DE CRIPTOGRAFIA BÁSICA ===")
    
    try:
        from atous_sec_network.core.crypto_utils import CryptoUtils
        
        # Teste de geração de bytes seguros
        random_bytes = CryptoUtils.generate_secure_random(32)
        log(f"✅ Bytes seguros gerados: {len(random_bytes)} bytes")
        
        # Teste de hash
        test_data = b"test data"
        hash_result = CryptoUtils.secure_hash(test_data)
        log(f"✅ Hash SHA256 gerado: {hash_result[:16]}...")
        
        # Teste de derivação de chave
        derived_key = CryptoUtils.derive_key("password", b"salt", 32)
        log(f"✅ Chave derivada: {len(derived_key)} bytes")
        
        return True
        
    except Exception as e:
        log(f"❌ Erro na criptografia: {str(e)}")
        return False

def test_rate_limiting():
    """Testa rate limiting básico"""
    log("⏱️ === TESTE DE RATE LIMITING ===")
    
    base_url = "http://127.0.0.1:8000/health"
    
    # Faz 5 requisições rápidas
    blocked_count = 0
    success_count = 0
    
    for i in range(5):
        try:
            response = requests.get(base_url, timeout=2)
            if response.status_code == 429:  # Too Many Requests
                blocked_count += 1
                log(f"⚠️ Requisição {i+1} bloqueada por rate limiting")
            elif response.status_code == 200:
                success_count += 1
                log(f"✅ Requisição {i+1} bem-sucedida")
            else:
                log(f"⚠️ Requisição {i+1} retornou status {response.status_code}")
        except Exception as e:
            log(f"❌ Erro na requisição {i+1}: {str(e)}")
        
        time.sleep(0.1)  # Pequena pausa
    
    log(f"📊 Rate Limiting - Sucessos: {success_count}, Bloqueios: {blocked_count}")
    return {"success_count": success_count, "blocked_count": blocked_count}

def test_security_detection():
    """Testa detecção básica de ameaças"""
    log("🛡️ === TESTE DE DETECÇÃO DE AMEAÇAS ===")
    
    base_url = "http://127.0.0.1:8000/health"
    
    # Testa com diferentes tipos de payloads suspeitos
    suspicious_payloads = [
        ("SQL Injection", "?id=1' OR '1'='1"),
        ("XSS", "?search=<script>alert('xss')</script>"),
        ("Path Traversal", "?file=../../../etc/passwd")
    ]
    
    results = []
    
    for threat_type, payload in suspicious_payloads:
        try:
            response = requests.get(f"{base_url}{payload}", timeout=5)
            blocked = response.status_code in [403, 400, 429]
            status = "🛡️ BLOQUEADO" if blocked else "⚠️ PERMITIDO"
            log(f"{status} - {threat_type}: Status {response.status_code}")
            results.append({
                "threat_type": threat_type,
                "payload": payload,
                "status_code": response.status_code,
                "blocked": blocked
            })
        except Exception as e:
            log(f"❌ Erro testando {threat_type}: {str(e)}")
            results.append({
                "threat_type": threat_type,
                "error": str(e)
            })
    
    return results

def main():
    """Função principal do teste"""
    log("🚀 Iniciando Teste Básico de Funcionalidades")
    log(f"🕒 Timestamp: {datetime.now().isoformat()}")
    
    # Executa todos os testes
    results = {
        "timestamp": datetime.now().isoformat(),
        "endpoints": test_basic_endpoints(),
        "crypto_working": test_crypto_utils(),
        "rate_limiting": test_rate_limiting(),
        "security_detection": test_security_detection()
    }
    
    # Calcula estatísticas
    endpoint_success_rate = sum(1 for ep in results["endpoints"] if ep.get("success", False)) / len(results["endpoints"]) * 100
    security_block_rate = sum(1 for sd in results["security_detection"] if sd.get("blocked", False)) / len(results["security_detection"]) * 100
    
    log("\n📊 === RESUMO FINAL ===")
    log(f"✅ Taxa de sucesso dos endpoints: {endpoint_success_rate:.1f}%")
    log(f"🔐 Criptografia básica: {'✅ Funcionando' if results['crypto_working'] else '❌ Com problemas'}")
    log(f"⏱️ Rate limiting: {results['rate_limiting']['success_count']} sucessos, {results['rate_limiting']['blocked_count']} bloqueios")
    log(f"🛡️ Taxa de bloqueio de ameaças: {security_block_rate:.1f}%")
    
    # Salva relatório
    with open("basic_functionality_report.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    log("💾 Relatório salvo em: basic_functionality_report.json")
    log("🎯 Teste básico concluído!")

if __name__ == "__main__":
    main()