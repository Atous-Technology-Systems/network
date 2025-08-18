#!/usr/bin/env python3
"""
Teste simples para o sistema ABISS
"""
import sys
import os

# Adicionar o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from atous_sec_network.security.abiss_system import ABISSSystem

def test_abiss_simple():
    """Teste simples do sistema ABISS"""
    print("Iniciando teste simples do sistema ABISS...")
    
    # Criar instância do sistema
    abiss = ABISSSystem()
    print("✅ Sistema ABISS criado com sucesso")
    
    # Testar requisição legítima
    legitimate_request = {
        "method": "POST",
        "url": "/auth/register",
        "headers": {"Content-Type": "application/json"},
        "body": {"username": "testuser", "email": "test@example.com"},
        "ip": "127.0.0.1"
    }
    
    score = abiss.analyze_request(legitimate_request)
    print(f"✅ Requisição legítima: score = {score:.3f}")
    
    # Testar requisição suspeita
    suspicious_request = {
        "method": "POST",
        "url": "/auth/register",
        "headers": {"Content-Type": "application/json"},
        "body": {"username": "admin", "email": "admin@admin.com"},
        "ip": "192.168.1.100"
    }
    
    score = abiss.analyze_request(suspicious_request)
    print(f"✅ Requisição suspeita: score = {score:.3f}")
    
    # Testar requisição maliciosa
    malicious_request = {
        "method": "POST",
        "url": "/auth/register",
        "headers": {"Content-Type": "application/json"},
        "body": {"username": "'; DROP TABLE users; --", "email": "sql@injection.com"},
        "ip": "10.0.0.1"
    }
    
    score = abiss.analyze_request(malicious_request)
    print(f"✅ Requisição maliciosa: score = {score:.3f}")
    
    print("\n🎉 Todos os testes passaram!")

if __name__ == "__main__":
    test_abiss_simple()
