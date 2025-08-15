#!/usr/bin/env python3
"""
Teste Final de Segurança - ATous Secure Network
Validação completa das funcionalidades de segurança em tempo real
"""

import requests
import json
import time
from datetime import datetime
import threading
import concurrent.futures

class SecurityTester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "server_status": None,
            "security_tests": {},
            "performance_tests": {},
            "vulnerability_tests": {},
            "summary": {}
        }
    
    def test_server_availability(self):
        """Testa se o servidor está disponível"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            self.results["server_status"] = {
                "available": True,
                "status_code": response.status_code,
                "response_time_ms": response.elapsed.total_seconds() * 1000
            }
            return True
        except Exception as e:
            self.results["server_status"] = {
                "available": False,
                "error": str(e)
            }
            return False
    
    def test_security_headers(self):
        """Testa cabeçalhos de segurança"""
        try:
            response = requests.get(f"{self.base_url}/health")
            headers = response.headers
            
            security_headers = {
                "x-content-type-options": headers.get("x-content-type-options"),
                "x-frame-options": headers.get("x-frame-options"),
                "x-xss-protection": headers.get("x-xss-protection"),
                "strict-transport-security": headers.get("strict-transport-security"),
                "content-security-policy": headers.get("content-security-policy")
            }
            
            self.results["security_tests"]["security_headers"] = {
                "status": "PASS" if all(security_headers.values()) else "FAIL",
                "headers": security_headers
            }
        except Exception as e:
            self.results["security_tests"]["security_headers"] = {
                "status": "ERROR",
                "error": str(e)
            }
    
    def test_encryption_endpoints(self):
        """Testa endpoints de criptografia"""
        encryption_endpoints = [
            "/api/crypto/encrypt",
            "/api/security/encrypt",
            "/encrypt"
        ]
        
        test_data = {"message": "security_test_message"}
        
        for endpoint in encryption_endpoints:
            try:
                response = requests.post(
                    f"{self.base_url}{endpoint}",
                    json=test_data,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.results["security_tests"][f"encryption_{endpoint.replace('/', '_')}"] = {
                        "status": "PASS",
                        "algorithm": data.get("algorithm"),
                        "key_id": data.get("key_id"),
                        "encrypted_data_length": len(data.get("encrypted_data", ""))
                    }
                else:
                    self.results["security_tests"][f"encryption_{endpoint.replace('/', '_')}"] = {
                        "status": "FAIL",
                        "status_code": response.status_code
                    }
            except Exception as e:
                self.results["security_tests"][f"encryption_{endpoint.replace('/', '_')}"] = {
                    "status": "ERROR",
                    "error": str(e)
                }
    
    def test_threat_detection(self):
        """Testa detecção de ameaças"""
        threats = {
            "sql_injection": "' OR '1'='1",
            "xss": "<script>alert('XSS')</script>",
            "path_traversal": "../../../etc/passwd",
            "command_injection": "; cat /etc/passwd"
        }
        
        for threat_type, payload in threats.items():
            try:
                response = requests.get(
                    f"{self.base_url}/health",
                    params={"test": payload},
                    timeout=5
                )
                
                # Status 403 indica que a ameaça foi detectada e bloqueada
                if response.status_code == 403:
                    status = "BLOCKED"
                elif response.status_code == 200:
                    status = "ALLOWED"
                else:
                    status = f"UNKNOWN_{response.status_code}"
                
                self.results["vulnerability_tests"][threat_type] = {
                    "status": status,
                    "status_code": response.status_code,
                    "payload": payload
                }
            except Exception as e:
                self.results["vulnerability_tests"][threat_type] = {
                    "status": "ERROR",
                    "error": str(e)
                }
    
    def test_rate_limiting(self):
        """Testa rate limiting"""
        def make_request():
            try:
                response = requests.get(f"{self.base_url}/health", timeout=2)
                return response.status_code
            except:
                return 0
        
        # Faz 20 requisições simultâneas
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(20)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        blocked_count = sum(1 for status in results if status == 429)
        success_count = sum(1 for status in results if status == 200)
        
        self.results["performance_tests"]["rate_limiting"] = {
            "total_requests": len(results),
            "successful_requests": success_count,
            "blocked_requests": blocked_count,
            "rate_limiting_active": blocked_count > 0
        }
    
    def test_system_metrics(self):
        """Testa métricas do sistema"""
        try:
            response = requests.get(f"{self.base_url}/api/metrics", timeout=5)
            if response.status_code == 200:
                metrics = response.json()
                self.results["performance_tests"]["system_metrics"] = {
                    "status": "AVAILABLE",
                    "uptime_seconds": metrics.get("system", {}).get("uptime_seconds"),
                    "memory_usage_mb": metrics.get("system", {}).get("memory_usage_mb"),
                    "cpu_percent": metrics.get("system", {}).get("cpu_percent"),
                    "threats_blocked": metrics.get("security", {}).get("threats_blocked")
                }
            else:
                self.results["performance_tests"]["system_metrics"] = {
                    "status": "UNAVAILABLE",
                    "status_code": response.status_code
                }
        except Exception as e:
            self.results["performance_tests"]["system_metrics"] = {
                "status": "ERROR",
                "error": str(e)
            }
    
    def generate_summary(self):
        """Gera resumo dos testes"""
        total_tests = 0
        passed_tests = 0
        
        # Conta testes de segurança
        for test_name, test_result in self.results["security_tests"].items():
            total_tests += 1
            if test_result.get("status") == "PASS":
                passed_tests += 1
        
        # Conta testes de vulnerabilidade (bloqueados são considerados como PASS)
        for test_name, test_result in self.results["vulnerability_tests"].items():
            total_tests += 1
            if test_result.get("status") == "BLOCKED":
                passed_tests += 1
        
        # Conta testes de performance
        for test_name, test_result in self.results["performance_tests"].items():
            total_tests += 1
            if test_result.get("status") in ["AVAILABLE", "PASS"] or test_result.get("rate_limiting_active"):
                passed_tests += 1
        
        self.results["summary"] = {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            "server_available": self.results["server_status"].get("available", False)
        }
    
    def run_all_tests(self):
        """Executa todos os testes de segurança"""
        print("🔒 Iniciando Testes de Segurança Completos")
        print("=" * 50)
        
        # Testa disponibilidade do servidor
        print("📡 Testando disponibilidade do servidor...")
        if not self.test_server_availability():
            print("❌ Servidor não disponível. Abortando testes.")
            return
        print(f"✅ Servidor disponível - {self.results['server_status']['status_code']}")
        
        # Testa cabeçalhos de segurança
        print("🛡️ Testando cabeçalhos de segurança...")
        self.test_security_headers()
        
        # Testa endpoints de criptografia
        print("🔐 Testando endpoints de criptografia...")
        self.test_encryption_endpoints()
        
        # Testa detecção de ameaças
        print("🚨 Testando detecção de ameaças...")
        self.test_threat_detection()
        
        # Testa rate limiting
        print("⏱️ Testando rate limiting...")
        self.test_rate_limiting()
        
        # Testa métricas do sistema
        print("📊 Testando métricas do sistema...")
        self.test_system_metrics()
        
        # Gera resumo
        self.generate_summary()
        
        print("\n" + "=" * 50)
        print("📋 RESUMO DOS TESTES DE SEGURANÇA")
        print("=" * 50)
        print(f"Total de testes: {self.results['summary']['total_tests']}")
        print(f"Testes aprovados: {self.results['summary']['passed_tests']}")
        print(f"Taxa de sucesso: {self.results['summary']['success_rate']:.1f}%")
        print(f"Servidor disponível: {'✅' if self.results['summary']['server_available'] else '❌'}")
        
        # Salva relatório
        report_file = "security_test_final_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Relatório salvo em: {report_file}")
        
        return self.results

if __name__ == "__main__":
    tester = SecurityTester()
    results = tester.run_all_tests()
    
    print("\n🎉 Testes de Segurança Concluídos!")