#!/usr/bin/env python3
"""
Testes Avançados de Segurança - ATous Secure Network
Testa vulnerabilidades específicas e ataques mais sofisticados
"""

import requests
import json
import time
import base64
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any


class AdvancedSecurityTester:
    """Classe para testes avançados de segurança"""
    
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = []
        
    def log_test(self, attack_type: str, payload: str, detected: bool, response_code: int, details: str = ""):
        """Registra resultado do teste"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "payload": payload,
            "detected": detected,
            "response_code": response_code,
            "details": details
        }
        self.results.append(result)
        status = "✅ DETECTADO" if detected else "❌ NÃO DETECTADO"
        print(f"[{attack_type}] {status} - {payload[:50]}...")
        
    def test_advanced_path_traversal(self):
        """Testa técnicas avançadas de path traversal"""
        print("\n🔍 Testando Path Traversal Avançado...")
        
        # Técnicas de bypass
        payloads = [
            # Double encoding
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            # Unicode encoding
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            # UTF-8 encoding
            "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
            # Null byte injection
            "../../../etc/passwd%00.jpg",
            # Mixed case
            "..\\..\\..\\WiNdOwS\\sYsTeM32\\dRiVeRs\\eTc\\hOsTs",
            # Long path
            "../" * 50 + "etc/passwd",
            # Overlong UTF-8
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
            # 16-bit Unicode
            "..%u002f..%u002f..%u002fetc%u002fpasswd"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/v1/status",
                    params={"file": payload},
                    timeout=5
                )
                
                detected = response.status_code in [400, 403, 406]
                self.log_test("Advanced Path Traversal", payload, detected, response.status_code)
                
            except Exception as e:
                print(f"Erro no teste: {e}")
                
            time.sleep(0.3)
            
    def test_advanced_sql_injection(self):
        """Testa técnicas avançadas de SQL injection"""
        print("\n🔍 Testando SQL Injection Avançado...")
        
        payloads = [
            # Time-based blind
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND (SELECT COUNT(*) FROM sysusers AS sys1, sysusers AS sys2, sysusers AS sys3, sysusers AS sys4, sysusers AS sys5, sysusers AS sys6, sysusers AS sys7, sysusers AS sys8) > 0--",
            # Boolean-based blind
            "1' AND (SELECT SUBSTRING(@@version,1,1))='M'--",
            # Union-based
            "1' UNION SELECT null,null,null,version()--",
            # Error-based
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # Second-order injection
            "admin'; INSERT INTO users VALUES('hacker','password'); --",
            # NoSQL injection
            "{'$ne': null}",
            "{'$regex': '.*'}",
            # LDAP injection in SQL context
            "*)(|(objectClass=*))"
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/v1/status",
                    json={"query": payload},
                    timeout=10  # Maior timeout para time-based
                )
                
                detected = response.status_code in [400, 403, 406]
                self.log_test("Advanced SQL Injection", payload, detected, response.status_code)
                
            except Exception as e:
                print(f"Erro no teste: {e}")
                
            time.sleep(0.3)
            
    def test_advanced_xss(self):
        """Testa técnicas avançadas de XSS"""
        print("\n🔍 Testando XSS Avançado...")
        
        payloads = [
            # Filter bypass
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<img src=x onerror=\"alert('XSS')\">",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            # Event handlers
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus><option>test</option></select>",
            # Data URI
            "<iframe src=\"data:text/html,<script>alert('XSS')</script>\"></iframe>",
            # SVG XSS
            "<svg><script>alert('XSS')</script></svg>",
            # CSS injection
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            # Template injection
            "{{7*7}}",
            "${7*7}",
            "#{7*7}"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/v1/status",
                    params={"search": payload},
                    timeout=5
                )
                
                detected = response.status_code in [400, 403, 406]
                self.log_test("Advanced XSS", payload, detected, response.status_code)
                
            except Exception as e:
                print(f"Erro no teste: {e}")
                
            time.sleep(0.3)
            
    def test_deserialization_attacks(self):
        """Testa ataques de deserialização"""
        print("\n🔍 Testando Ataques de Deserialização...")
        
        # Python pickle payload (base64 encoded)
        pickle_payload = base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode()
        
        payloads = [
            # Java deserialization
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAABYXQAAWJ4",
            # Python pickle
            pickle_payload,
            # .NET BinaryFormatter
            "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAAA=",
            # PHP serialization
            'O:8:"stdClass":1:{s:4:"test";s:4:"exec";}'  
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/v1/status",
                    json={"data": payload},
                    timeout=5
                )
                
                detected = response.status_code in [400, 403, 406]
                self.log_test("Deserialization", payload[:50], detected, response.status_code)
                
            except Exception as e:
                print(f"Erro no teste: {e}")
                
            time.sleep(0.3)
            
    def test_ssrf_attacks(self):
        """Testa ataques de Server-Side Request Forgery"""
        print("\n🔍 Testando SSRF Attacks...")
        
        payloads = [
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "file:///etc/passwd",
            "ftp://evil.com/",
            "gopher://127.0.0.1:6379/_INFO",  # Redis
            "dict://127.0.0.1:11211/stats",  # Memcached
            "http://[::1]:80/",  # IPv6 localhost
            "http://0x7f000001/",  # Hex encoded localhost
            "http://2130706433/"  # Decimal encoded localhost
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/v1/status",
                    json={"url": payload},
                    timeout=5
                )
                
                detected = response.status_code in [400, 403, 406]
                self.log_test("SSRF", payload, detected, response.status_code)
                
            except Exception as e:
                print(f"Erro no teste: {e}")
                
            time.sleep(0.3)
            
    def test_header_injection(self):
        """Testa injeção de cabeçalhos HTTP"""
        print("\n🔍 Testando Header Injection...")
        
        payloads = [
            "test\r\nX-Injected: true",
            "test\nSet-Cookie: admin=true",
            "test\r\nLocation: http://evil.com",
            "test\r\n\r\n<script>alert('XSS')</script>",
            "test%0d%0aSet-Cookie:%20admin=true",
            "test%0aX-Forwarded-For:%20127.0.0.1"
        ]
        
        for payload in payloads:
            try:
                headers = {"X-Custom-Header": payload}
                response = self.session.get(
                    f"{self.base_url}/api/v1/status",
                    headers=headers,
                    timeout=5
                )
                
                detected = response.status_code in [400, 403, 406]
                self.log_test("Header Injection", payload, detected, response.status_code)
                
            except Exception as e:
                print(f"Erro no teste: {e}")
                
            time.sleep(0.3)
            
    def test_prototype_pollution(self):
        """Testa ataques de Prototype Pollution"""
        print("\n🔍 Testando Prototype Pollution...")
        
        payloads = [
            {"__proto__": {"admin": True}},
            {"constructor": {"prototype": {"admin": True}}},
            {"__proto__.admin": True},
            {"constructor.prototype.admin": True}
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/v1/status",
                    json=payload,
                    timeout=5
                )
                
                detected = response.status_code in [400, 403, 406]
                self.log_test("Prototype Pollution", str(payload), detected, response.status_code)
                
            except Exception as e:
                print(f"Erro no teste: {e}")
                
            time.sleep(0.3)
            
    def run_advanced_tests(self):
        """Executa todos os testes avançados"""
        print("🛡️ Iniciando Testes Avançados de Penetração")
        print("=" * 50)
        
        # Verificar disponibilidade do servidor
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            if response.status_code != 200:
                print(f"❌ Servidor retornou status {response.status_code}")
                return
        except Exception as e:
            print(f"❌ Erro ao conectar com servidor: {e}")
            return
            
        print("✅ Servidor disponível")
        
        # Executar testes avançados
        self.test_advanced_path_traversal()
        self.test_advanced_sql_injection()
        self.test_advanced_xss()
        self.test_deserialization_attacks()
        self.test_ssrf_attacks()
        self.test_header_injection()
        self.test_prototype_pollution()
        
        # Gerar relatório
        self.generate_advanced_report()
        
    def generate_advanced_report(self):
        """Gera relatório dos testes avançados"""
        print("\n📊 Relatório de Testes Avançados")
        print("=" * 40)
        
        total_tests = len(self.results)
        detected_attacks = sum(1 for r in self.results if r["detected"])
        detection_rate = (detected_attacks / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total de testes avançados: {total_tests}")
        print(f"Ataques detectados: {detected_attacks}")
        print(f"Taxa de detecção: {detection_rate:.1f}%")
        
        # Agrupar por tipo de ataque
        attack_types = {}
        for result in self.results:
            attack_type = result["attack_type"]
            if attack_type not in attack_types:
                attack_types[attack_type] = {"total": 0, "detected": 0}
            attack_types[attack_type]["total"] += 1
            if result["detected"]:
                attack_types[attack_type]["detected"] += 1
                
        print("\nDetecção por tipo de ataque avançado:")
        for attack_type, stats in attack_types.items():
            rate = (stats["detected"] / stats["total"] * 100) if stats["total"] > 0 else 0
            print(f"  {attack_type}: {stats['detected']}/{stats['total']} ({rate:.1f}%)")
            
        # Salvar relatório
        report_file = f"advanced_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({
                "summary": {
                    "total_tests": total_tests,
                    "detected_attacks": detected_attacks,
                    "detection_rate": detection_rate,
                    "attack_types": attack_types
                },
                "detailed_results": self.results
            }, f, indent=2, ensure_ascii=False)
            
        print(f"\n📄 Relatório avançado salvo em: {report_file}")
        
        # Análise de segurança
        if detection_rate >= 90:
            print("\n✅ EXCELENTE: Defesas muito robustas contra ataques avançados")
        elif detection_rate >= 70:
            print("\n✅ BOM: Defesas adequadas, mas podem ser melhoradas")
        elif detection_rate >= 50:
            print("\n⚠️ MODERADO: Algumas vulnerabilidades detectadas")
        else:
            print("\n❌ CRÍTICO: Muitas vulnerabilidades não detectadas")
            print("Recomenda-se implementar controles de segurança adicionais.")


def main():
    """Função principal"""
    import sys
    
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:8001"
        
    print(f"🎯 Testando servidor: {base_url}")
    
    tester = AdvancedSecurityTester(base_url)
    tester.run_advanced_tests()
    
    print("\n🏁 Testes avançados de penetração concluídos.")


if __name__ == "__main__":
    main()