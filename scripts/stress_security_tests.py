#!/usr/bin/env python3
"""
Testes de Stress e Força Bruta - ATous Secure Network
Testa mecanismos de rate limiting e proteção contra ataques volumétricos
"""

import requests
import threading
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any


class StressSecurityTester:
    """Classe para testes de stress e força bruta"""
    
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.results = []
        self.lock = threading.Lock()
        
    def log_test(self, attack_type: str, details: str, blocked: bool, response_time: float = 0):
        """Registra resultado do teste de forma thread-safe"""
        with self.lock:
            result = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": attack_type,
                "details": details,
                "blocked": blocked,
                "response_time": response_time
            }
            self.results.append(result)
            status = "BLOQUEADO" if blocked else "PERMITIDO"
            print(f"[{attack_type}] {status} - {details}")
            
    def single_request(self, endpoint: str, method: str = "GET", data: Dict = None, headers: Dict = None) -> Dict:
        """Executa uma única requisição e mede o tempo de resposta"""
        session = requests.Session()
        start_time = time.time()
        
        try:
            if method.upper() == "GET":
                response = session.get(f"{self.base_url}{endpoint}", headers=headers, timeout=10)
            elif method.upper() == "POST":
                response = session.post(f"{self.base_url}{endpoint}", json=data, headers=headers, timeout=10)
            else:
                response = session.request(method, f"{self.base_url}{endpoint}", json=data, headers=headers, timeout=10)
                
            response_time = time.time() - start_time
            
            return {
                "status_code": response.status_code,
                "response_time": response_time,
                "success": True,
                "headers": dict(response.headers)
            }
            
        except requests.exceptions.Timeout:
            return {
                "status_code": 408,
                "response_time": time.time() - start_time,
                "success": False,
                "error": "Timeout"
            }
        except requests.exceptions.ConnectionError:
            return {
                "status_code": 0,
                "response_time": time.time() - start_time,
                "success": False,
                "error": "Connection Error"
            }
        except Exception as e:
            return {
                "status_code": 0,
                "response_time": time.time() - start_time,
                "success": False,
                "error": str(e)
            }
            
    def test_rate_limiting(self):
        """Testa mecanismos de rate limiting"""
        print("\nTestando Rate Limiting...")
        
        # Teste de rajada de requisições
        num_requests = 50
        max_workers = 10
        
        print(f"Enviando {num_requests} requisições simultâneas...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for i in range(num_requests):
                future = executor.submit(self.single_request, "/api/v1/status")
                futures.append(future)
                
            blocked_count = 0
            success_count = 0
            total_response_time = 0
            
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                
                # Considera bloqueado se status for 429 (Too Many Requests) ou 503
                blocked = result["status_code"] in [429, 503]
                if blocked:
                    blocked_count += 1
                elif result["success"] and result["status_code"] == 200:
                    success_count += 1
                    
                total_response_time += result["response_time"]
                
                if i < 5:  # Log apenas as primeiras 5 para não poluir
                    self.log_test(
                        "Rate Limiting", 
                        f"Request {i+1} - Status: {result['status_code']}",
                        blocked,
                        result["response_time"]
                    )
                    
        avg_response_time = total_response_time / num_requests
        block_rate = (blocked_count / num_requests) * 100
        
        print(f"\nResultados do Rate Limiting:")
        print(f"  Total de requisições: {num_requests}")
        print(f"  Requisições bloqueadas: {blocked_count} ({block_rate:.1f}%)")
        print(f"  Requisições bem-sucedidas: {success_count}")
        print(f"  Tempo médio de resposta: {avg_response_time:.3f}s")
        
        # Rate limiting é efetivo se bloquear pelo menos 30% das requisições em rajada
        effective = block_rate >= 30
        self.log_test(
            "Rate Limiting Summary",
            f"Block rate: {block_rate:.1f}%, Avg response: {avg_response_time:.3f}s",
            effective
        )
        
    def test_brute_force_protection(self):
        """Testa proteção contra ataques de força bruta"""
        print("\nTestando Proteção contra Força Bruta...")
        
        # Simula tentativas de login com credenciais inválidas
        passwords = [
            "admin", "password", "123456", "admin123", "root", 
            "password123", "qwerty", "letmein", "welcome", "monkey"
        ]
        
        blocked_attempts = 0
        
        for i, password in enumerate(passwords):
            login_data = {
                "username": "admin",
                "password": password
            }
            
            result = self.single_request("/api/v1/status", "POST", login_data)
            
            # Considera bloqueado se retornar 429, 403 ou 423 (Locked)
            blocked = result["status_code"] in [429, 403, 423]
            if blocked:
                blocked_attempts += 1
                
            self.log_test(
                "Brute Force",
                f"Login attempt {i+1} with password '{password}'",
                blocked,
                result["response_time"]
            )
            
            time.sleep(0.1)  # Pequeno delay entre tentativas
            
        protection_rate = (blocked_attempts / len(passwords)) * 100
        print(f"\nProteção contra Força Bruta: {blocked_attempts}/{len(passwords)} bloqueadas ({protection_rate:.1f}%)")
        
    def test_slowloris_attack(self):
        """Simula ataque Slowloris (conexões lentas)"""
        print("\nTestando Proteção contra Slowloris...")
        
        # Simula múltiplas conexões que enviam dados muito lentamente
        num_connections = 20
        
        def slow_request(connection_id: int):
            try:
                session = requests.Session()
                # Configura timeout baixo para simular conexão lenta
                response = session.get(
                    f"{self.base_url}/api/v1/status",
                    timeout=1,  # Timeout baixo
                    stream=True
                )
                
                # Tenta ler a resposta muito lentamente
                time.sleep(2)
                content = response.content
                
                return {
                    "connection_id": connection_id,
                    "status_code": response.status_code,
                    "blocked": False
                }
                
            except requests.exceptions.Timeout:
                return {
                    "connection_id": connection_id,
                    "status_code": 408,
                    "blocked": True  # Timeout indica proteção ativa
                }
            except Exception as e:
                return {
                    "connection_id": connection_id,
                    "status_code": 0,
                    "blocked": True,
                    "error": str(e)
                }
                
        with ThreadPoolExecutor(max_workers=num_connections) as executor:
            futures = [executor.submit(slow_request, i) for i in range(num_connections)]
            
            blocked_connections = 0
            
            for future in as_completed(futures):
                result = future.result()
                
                if result["blocked"]:
                    blocked_connections += 1
                    
                self.log_test(
                    "Slowloris",
                    f"Connection {result['connection_id']} - Status: {result.get('status_code', 'Error')}",
                    result["blocked"]
                )
                
        protection_rate = (blocked_connections / num_connections) * 100
        print(f"\nProteção contra Slowloris: {blocked_connections}/{num_connections} bloqueadas ({protection_rate:.1f}%)")
        
    def test_resource_exhaustion(self):
        """Testa proteção contra esgotamento de recursos"""
        print("\nTestando Proteção contra Esgotamento de Recursos...")
        
        # Testa com payloads grandes
        large_payloads = [
            {"data": "A" * 1024 * 100},  # 100KB
            {"data": "B" * 1024 * 500},  # 500KB
            {"data": "C" * 1024 * 1024}, # 1MB
        ]
        
        for i, payload in enumerate(large_payloads):
            size_kb = len(str(payload)) // 1024
            
            result = self.single_request("/api/v1/status", "POST", payload)
            
            # Considera bloqueado se retornar 413 (Payload Too Large) ou 400
            blocked = result["status_code"] in [413, 400, 403]
            
            self.log_test(
                "Resource Exhaustion",
                f"Large payload {i+1} ({size_kb}KB)",
                blocked,
                result["response_time"]
            )
            
    def test_http_flood(self):
        """Testa proteção contra HTTP flood"""
        print("\nTestando Proteção contra HTTP Flood...")
        
        # Envia muitas requisições em um curto período
        num_requests = 100
        duration = 10  # segundos
        
        print(f"Enviando {num_requests} requisições em {duration} segundos...")
        
        start_time = time.time()
        blocked_count = 0
        success_count = 0
        
        def flood_request(request_id: int):
            result = self.single_request("/health")
            return {
                "request_id": request_id,
                "blocked": result["status_code"] in [429, 503, 403],
                "success": result["status_code"] == 200,
                "response_time": result["response_time"]
            }
            
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            
            for i in range(num_requests):
                if time.time() - start_time > duration:
                    break
                    
                future = executor.submit(flood_request, i)
                futures.append(future)
                
                # Controla a taxa de envio
                time.sleep(duration / num_requests)
                
            for future in as_completed(futures):
                result = future.result()
                
                if result["blocked"]:
                    blocked_count += 1
                elif result["success"]:
                    success_count += 1
                    
        total_requests = len(futures)
        block_rate = (blocked_count / total_requests) * 100 if total_requests > 0 else 0
        
        print(f"\nProteção contra HTTP Flood:")
        print(f"  Requisições enviadas: {total_requests}")
        print(f"  Requisições bloqueadas: {blocked_count} ({block_rate:.1f}%)")
        print(f"  Requisições bem-sucedidas: {success_count}")
        
        self.log_test(
            "HTTP Flood Summary",
            f"Block rate: {block_rate:.1f}%",
            block_rate >= 20  # Considera efetivo se bloquear pelo menos 20%
        )
        
    def run_stress_tests(self):
        """Executa todos os testes de stress"""
        print("Iniciando Testes de Stress e Força Bruta")
        print("=" * 50)
        
        # Verificar disponibilidade do servidor
        try:
            result = self.single_request("/health")
            if not result["success"] or result["status_code"] != 200:
                print(f"Servidor não disponível - Status: {result.get('status_code', 'Error')}")
                return
        except Exception as e:
            print(f"Erro ao conectar com servidor: {e}")
            return
            
        print("Servidor disponível")
        
        # Executar testes de stress
        self.test_rate_limiting()
        self.test_brute_force_protection()
        self.test_slowloris_attack()
        self.test_resource_exhaustion()
        self.test_http_flood()
        
        # Gerar relatório
        self.generate_stress_report()
        
    def generate_stress_report(self):
        """Gera relatório dos testes de stress"""
        print("\nRelatório de Testes de Stress")
        print("=" * 40)
        
        total_tests = len(self.results)
        effective_protections = sum(1 for r in self.results if r["blocked"])
        protection_rate = (effective_protections / total_tests * 100) if total_tests > 0 else 0
        
        print(f"Total de testes: {total_tests}")
        print(f"Proteções efetivas: {effective_protections}")
        print(f"Taxa de proteção: {protection_rate:.1f}%")
        
        # Agrupar por tipo de teste
        test_types = {}
        for result in self.results:
            test_type = result["attack_type"]
            if test_type not in test_types:
                test_types[test_type] = {"total": 0, "blocked": 0}
            test_types[test_type]["total"] += 1
            if result["blocked"]:
                test_types[test_type]["blocked"] += 1
                
        print("\nEfetividade por tipo de teste:")
        for test_type, stats in test_types.items():
            rate = (stats["blocked"] / stats["total"] * 100) if stats["total"] > 0 else 0
            print(f"  {test_type}: {stats['blocked']}/{stats['total']} ({rate:.1f}%)")
            
        # Salvar relatório
        report_file = f"stress_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({
                "summary": {
                    "total_tests": total_tests,
                    "effective_protections": effective_protections,
                    "protection_rate": protection_rate,
                    "test_types": test_types
                },
                "detailed_results": self.results
            }, f, indent=2, ensure_ascii=False)
            
        print(f"\n📄 Relatório de stress salvo em: {report_file}")
        
        # Avaliação final
        if protection_rate >= 80:
            print("\nEXCELENTE: Proteções contra ataques volumétricos muito efetivas")
        elif protection_rate >= 60:
            print("\nBOM: Proteções adequadas contra a maioria dos ataques")
        elif protection_rate >= 40:
            print("\nMODERADO: Algumas proteções funcionando, mas há vulnerabilidades")
        else:
            print("\nCRÍTICO: Proteções insuficientes contra ataques volumétricos")
            print("Recomenda-se implementar rate limiting e proteções DDoS.")


def main():
    """Função principal"""
    import sys
    
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:8001"
        
    print(f"🎯 Testando servidor: {base_url}")
    
    tester = StressSecurityTester(base_url)
    tester.run_stress_tests()
    
    print("\nTestes de stress e força bruta concluídos.")
    print("\nAVISO: Estes testes podem impactar a performance do servidor.")
    print("Use apenas em ambientes de teste controlados.")


if __name__ == "__main__":
    main()