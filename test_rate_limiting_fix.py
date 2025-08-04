#!/usr/bin/env python3
"""Teste TDD para correção do Rate Limiting

Este teste verifica se o rate limiting está configurado adequadamente
para permitir testes de desenvolvimento.
"""

import requests
import time
import json
from datetime import datetime

class TestRateLimitingFix:
    def __init__(self):
        self.base_url = "http://127.0.0.1:8000"
        self.session = requests.Session()
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'test_name': 'Rate Limiting Fix Test',
            'tests': {}
        }
    
    def log(self, message):
        """Log com timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def test_basic_connectivity(self):
        """Testa conectividade básica"""
        self.log("Testando conectividade básica...")
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            success = response.status_code == 200
            self.results['tests']['basic_connectivity'] = {
                'status': 'PASS' if success else 'FAIL',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
            self.log(f"Conectividade: {'✓' if success else '✗'} (Status: {response.status_code})")
            return success
        except Exception as e:
            self.results['tests']['basic_connectivity'] = {
                'status': 'ERROR',
                'error': str(e)
            }
            self.log(f"Erro de conectividade: {e}")
            return False
    
    def test_rate_limiting_permissive(self):
        """Testa se o rate limiting permite requisições normais de desenvolvimento"""
        self.log("Testando rate limiting permissivo...")
        
        # Deve permitir pelo menos 20 requisições em 1 minuto para desenvolvimento
        target_requests = 20
        successful_requests = 0
        blocked_requests = 0
        errors = []
        
        start_time = time.time()
        
        for i in range(target_requests):
            try:
                response = self.session.get(f"{self.base_url}/health", timeout=5)
                if response.status_code == 200:
                    successful_requests += 1
                elif response.status_code == 429:
                    blocked_requests += 1
                    self.log(f"Requisição {i+1} bloqueada (429)")
                else:
                    errors.append(f"Status {response.status_code} na requisição {i+1}")
                
                # Pequeno delay para simular uso normal
                time.sleep(0.1)
                
            except Exception as e:
                errors.append(f"Erro na requisição {i+1}: {e}")
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Para desenvolvimento, esperamos pelo menos 80% de sucesso
        success_rate = (successful_requests / target_requests) * 100
        test_passed = success_rate >= 80.0
        
        self.results['tests']['rate_limiting_permissive'] = {
            'status': 'PASS' if test_passed else 'FAIL',
            'target_requests': target_requests,
            'successful_requests': successful_requests,
            'blocked_requests': blocked_requests,
            'success_rate': success_rate,
            'total_time': total_time,
            'errors': errors,
            'requirement': 'Deve permitir pelo menos 80% de sucesso em 20 requisições'
        }
        
        self.log(f"Rate Limiting: {'✓' if test_passed else '✗'}")
        self.log(f"  Sucessos: {successful_requests}/{target_requests} ({success_rate:.1f}%)")
        self.log(f"  Bloqueios: {blocked_requests}")
        self.log(f"  Tempo total: {total_time:.2f}s")
        
        return test_passed
    
    def test_rate_limiting_configuration(self):
        """Testa se a configuração de rate limiting está adequada"""
        self.log("Verificando configuração de rate limiting...")
        
        try:
            # Tenta acessar endpoint de configuração se disponível
            response = self.session.get(f"{self.base_url}/api/v1/middleware/config", timeout=5)
            
            if response.status_code == 200:
                config = response.json()
                self.results['tests']['rate_limiting_config'] = {
                    'status': 'INFO',
                    'config_available': True,
                    'config': config
                }
                self.log("Configuração obtida com sucesso")
            else:
                self.results['tests']['rate_limiting_config'] = {
                    'status': 'INFO',
                    'config_available': False,
                    'status_code': response.status_code
                }
                self.log(f"Configuração não disponível (Status: {response.status_code})")
                
        except Exception as e:
            self.results['tests']['rate_limiting_config'] = {
                'status': 'INFO',
                'config_available': False,
                'error': str(e)
            }
            self.log(f"Erro ao obter configuração: {e}")
    
    def run_all_tests(self):
        """Executa todos os testes"""
        self.log("=== INICIANDO TESTES DE RATE LIMITING ===")
        
        # Teste 1: Conectividade básica
        connectivity_ok = self.test_basic_connectivity()
        
        if not connectivity_ok:
            self.log("❌ Servidor não está respondendo. Abortando testes.")
            return False
        
        # Teste 2: Rate limiting permissivo
        rate_limiting_ok = self.test_rate_limiting_permissive()
        
        # Teste 3: Configuração (informativo)
        self.test_rate_limiting_configuration()
        
        # Resultado final
        all_tests_passed = connectivity_ok and rate_limiting_ok
        
        self.results['overall_status'] = 'PASS' if all_tests_passed else 'FAIL'
        self.results['summary'] = {
            'connectivity': connectivity_ok,
            'rate_limiting_permissive': rate_limiting_ok,
            'recommendation': 'Ajustar configurações de rate limiting para desenvolvimento' if not rate_limiting_ok else 'Rate limiting adequado para desenvolvimento'
        }
        
        self.log("\n=== RESULTADO FINAL ===")
        self.log(f"Status: {'✓ PASS' if all_tests_passed else '✗ FAIL'}")
        
        if not rate_limiting_ok:
            self.log("\n🔧 AÇÃO NECESSÁRIA:")
            self.log("   - Ajustar configurações de rate limiting")
            self.log("   - Aumentar limites para ambiente de desenvolvimento")
            self.log("   - Implementar perfis de configuração (dev/prod)")
        
        return all_tests_passed
    
    def save_results(self):
        """Salva resultados em arquivo JSON"""
        filename = "rate_limiting_test_results.json"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            self.log(f"Resultados salvos em: {filename}")
        except Exception as e:
            self.log(f"Erro ao salvar resultados: {e}")

if __name__ == "__main__":
    tester = TestRateLimitingFix()
    success = tester.run_all_tests()
    tester.save_results()
    
    exit(0 if success else 1)