#!/usr/bin/env python3
"""
Script de Teste Completo - ATous Secure Network
Testa todas as funcionalidades: endpoints, WebSockets, criptografia, segurança
"""

import requests
import json
import time
import asyncio
import websockets
from datetime import datetime

class ATousTestSuite:
    def __init__(self, base_url="http://127.0.0.1:8000"):
        self.base_url = base_url
        self.ws_url = base_url.replace("http", "ws")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ATous-Test-Suite/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        self.results = {
            'endpoints': {},
            'websockets': {},
            'security': {},
            'crypto': {},
            'performance': {}
        }
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def test_endpoints(self):
        """Testa todos os endpoints da API"""
        self.log("=== TESTANDO ENDPOINTS ===")
        
        endpoints = [
            ("/", "GET", "Root endpoint"),
            ("/health", "GET", "Health check"),
            ("/docs", "GET", "API Documentation"),
            ("/openapi.json", "GET", "OpenAPI Schema"),
            ("/api/info", "GET", "API Info"),
            ("/api/security/status", "GET", "Security Status"),
            ("/api/metrics", "GET", "System Metrics"),
        ]
        
        for endpoint, method, description in endpoints:
            try:
                start_time = time.time()
                response = self.session.request(method, f"{self.base_url}{endpoint}")
                response_time = (time.time() - start_time) * 1000
                
                self.results['endpoints'][endpoint] = {
                    'status': response.status_code,
                    'response_time_ms': round(response_time, 2),
                    'description': description,
                    'success': response.status_code < 400
                }
                
                status_icon = "✅" if response.status_code < 400 else "❌"
                self.log(f"{status_icon} {method} {endpoint} - {response.status_code} ({response_time:.1f}ms) - {description}")
                
                if response.status_code < 400:
                    try:
                        if 'application/json' in response.headers.get('content-type', ''):
                            data = response.json()
                            self.log(f"   Response: {json.dumps(data, indent=2)[:100]}...")
                    except:
                        self.log(f"   Response: {response.text[:100]}...")
                else:
                    self.log(f"   Error: {response.text[:100]}...")
                    
            except Exception as e:
                self.log(f"❌ {method} {endpoint} - ERROR: {str(e)}")
                self.results['endpoints'][endpoint] = {
                    'status': 0,
                    'error': str(e),
                    'success': False
                }
    
    def test_security_features(self):
        """Testa funcionalidades de segurança"""
        self.log("\n=== TESTANDO SEGURANÇA ===")
        
        # Teste de rate limiting
        self.log("Testando Rate Limiting...")
        rate_limit_results = []
        for i in range(10):
            try:
                response = self.session.get(f"{self.base_url}/health")
                rate_limit_results.append(response.status_code)
                time.sleep(0.1)
            except Exception as e:
                rate_limit_results.append(f"ERROR: {e}")
        
        self.results['security']['rate_limiting'] = {
            'requests_sent': 10,
            'responses': rate_limit_results,
            'blocked_count': sum(1 for r in rate_limit_results if r == 429)
        }
        
        # Teste de detecção de ameaças
        self.log("Testando Detecção de Ameaças...")
        threat_tests = [
            ("SQL Injection", "/health?id=1' OR '1'='1"),
            ("XSS", "/health?search=<script>alert('xss')</script>"),
            ("Path Traversal", "/health?file=../../../etc/passwd"),
            ("Command Injection", "/health?cmd=; ls -la")
        ]
        
        for threat_name, malicious_endpoint in threat_tests:
            try:
                response = self.session.get(f"{self.base_url}{malicious_endpoint}")
                blocked = response.status_code == 403
                self.results['security'][f'threat_{threat_name.lower().replace(" ", "_")}'] = {
                    'blocked': blocked,
                    'status_code': response.status_code
                }
                status_icon = "🛡️" if blocked else "⚠️"
                self.log(f"{status_icon} {threat_name}: {'BLOCKED' if blocked else 'ALLOWED'} ({response.status_code})")
            except Exception as e:
                self.log(f"❌ {threat_name}: ERROR - {str(e)}")
    
    async def test_websockets(self):
        """Testa funcionalidades WebSocket"""
        self.log("\n=== TESTANDO WEBSOCKETS ===")
        
        try:
            # Tenta conectar ao WebSocket (se disponível)
            ws_endpoints = [
                "/ws",
                "/api/ws",
                "/websocket"
            ]
            
            for endpoint in ws_endpoints:
                try:
                    uri = f"{self.ws_url}{endpoint}"
                    self.log(f"Tentando conectar ao WebSocket: {uri}")
                    
                    async with websockets.connect(uri) as websocket:
                        self.log(f"✅ WebSocket conectado: {endpoint}")
                        
                        # Envia mensagem de teste
                        test_message = {"type": "ping", "timestamp": time.time()}
                        await websocket.send(json.dumps(test_message))
                        
                        # Aguarda resposta
                        response = await asyncio.wait_for(websocket.recv(), timeout=5)
                        self.log(f"📨 Resposta recebida: {response[:100]}...")
                        
                        self.results['websockets'][endpoint] = {
                            'connected': True,
                            'response': response
                        }
                        break
                        
                except Exception as e:
                    self.log(f"❌ WebSocket {endpoint}: {str(e)}")
                    self.results['websockets'][endpoint] = {
                        'connected': False,
                        'error': str(e)
                    }
                    
        except Exception as e:
            self.log(f"❌ Erro geral no teste de WebSocket: {str(e)}")
    
    def test_crypto_features(self):
        """Testa funcionalidades de criptografia"""
        self.log("\n=== TESTANDO CRIPTOGRAFIA ===")
        
        try:
            # Teste de endpoint de criptografia (se disponível)
            crypto_endpoints = [
                "/api/crypto/encrypt",
                "/api/security/encrypt",
                "/encrypt"
            ]
            
            test_data = {"message": "Hello, ATous Secure Network!"}
            
            for endpoint in crypto_endpoints:
                try:
                    response = self.session.post(
                        f"{self.base_url}{endpoint}",
                        json=test_data
                    )
                    
                    if response.status_code < 400:
                        self.log(f"✅ Criptografia {endpoint}: {response.status_code}")
                        self.results['crypto'][endpoint] = {
                            'available': True,
                            'status_code': response.status_code,
                            'response': response.json() if 'json' in response.headers.get('content-type', '') else response.text
                        }
                    else:
                        self.log(f"❌ Criptografia {endpoint}: {response.status_code}")
                        
                except Exception as e:
                    self.log(f"❌ Erro no teste de criptografia {endpoint}: {str(e)}")
                    
        except Exception as e:
            self.log(f"❌ Erro geral no teste de criptografia: {str(e)}")
    
    def test_performance(self):
        """Testa performance da aplicação"""
        self.log("\n=== TESTANDO PERFORMANCE ===")
        
        # Teste de carga simples
        self.log("Executando teste de carga (50 requisições)...")
        
        response_times = []
        success_count = 0
        
        for i in range(50):
            try:
                start_time = time.time()
                response = self.session.get(f"{self.base_url}/health")
                response_time = (time.time() - start_time) * 1000
                response_times.append(response_time)
                
                if response.status_code < 400:
                    success_count += 1
                    
                if i % 10 == 0:
                    self.log(f"Progresso: {i+1}/50 requisições")
                    
            except Exception as e:
                self.log(f"Erro na requisição {i+1}: {str(e)}")
        
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
            
            self.results['performance'] = {
                'total_requests': 50,
                'successful_requests': success_count,
                'success_rate': (success_count / 50) * 100,
                'avg_response_time_ms': round(avg_response_time, 2),
                'min_response_time_ms': round(min_response_time, 2),
                'max_response_time_ms': round(max_response_time, 2)
            }
            
            self.log(f"📊 Performance Results:")
            self.log(f"   Taxa de sucesso: {success_count}/50 ({(success_count/50)*100:.1f}%)")
            self.log(f"   Tempo médio: {avg_response_time:.1f}ms")
            self.log(f"   Tempo mín/máx: {min_response_time:.1f}ms / {max_response_time:.1f}ms")
    
    def generate_report(self):
        """Gera relatório final dos testes"""
        self.log("\n=== RELATÓRIO FINAL ===")
        
        # Estatísticas gerais
        total_endpoints = len(self.results['endpoints'])
        successful_endpoints = sum(1 for ep in self.results['endpoints'].values() if ep.get('success', False))
        
        self.log(f"📈 Endpoints: {successful_endpoints}/{total_endpoints} funcionando")
        
        # Salva relatório em arquivo
        report = {
            'timestamp': datetime.now().isoformat(),
            'test_results': self.results,
            'summary': {
                'total_endpoints_tested': total_endpoints,
                'successful_endpoints': successful_endpoints,
                'endpoint_success_rate': (successful_endpoints / total_endpoints * 100) if total_endpoints > 0 else 0
            }
        }
        
        with open('complete_functionality_test_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.log(f"📄 Relatório salvo em: complete_functionality_test_report.json")
        
        return report
    
    async def run_all_tests(self):
        """Executa todos os testes"""
        self.log("🚀 Iniciando Teste Completo do ATous Secure Network")
        self.log(f"🎯 URL Base: {self.base_url}")
        
        # Testa se o servidor está respondendo
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            self.log(f"✅ Servidor respondendo: {response.status_code}")
        except Exception as e:
            self.log(f"❌ Servidor não está respondendo: {str(e)}")
            return
        
        # Executa todos os testes
        self.test_endpoints()
        self.test_security_features()
        await self.test_websockets()
        self.test_crypto_features()
        self.test_performance()
        
        # Gera relatório final
        report = self.generate_report()
        
        self.log("\n🎉 Teste Completo Finalizado!")
        return report

if __name__ == "__main__":
    async def main():
        test_suite = ATousTestSuite()
        await test_suite.run_all_tests()
    
    asyncio.run(main())