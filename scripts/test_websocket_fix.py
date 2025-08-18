#!/usr/bin/env python3
"""
Teste TDD para correção de WebSocket - ATous Secure Network
Este teste deve falhar inicialmente e guiar as correções necessárias
"""

import asyncio
import websockets
import json
import time
from datetime import datetime

class WebSocketTestSuite:
    def __init__(self, base_url="ws://127.0.0.1:8000"):
        self.base_url = base_url
        self.results = {
            'endpoints_tested': [],
            'successful_connections': 0,
            'failed_connections': 0,
            'errors': [],
            'test_summary': {}
        }
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    async def test_websocket_endpoint(self, endpoint):
        """Testa um endpoint WebSocket específico"""
        uri = f"{self.base_url}{endpoint}"
        self.log(f"Testando WebSocket: {uri}")
        
        try:
            # Conecta sem timeout para evitar o erro atual
            async with websockets.connect(uri) as websocket:
                self.log(f" Conectado com sucesso: {endpoint}")
                
                # Envia mensagem de teste
                test_message = {
                    "type": "ping",
                    "message": "test_connection",
                    "timestamp": time.time()
                }
                
                await websocket.send(json.dumps(test_message))
                self.log(f" Mensagem enviada: {test_message}")
                
                # Aguarda resposta com timeout manual
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    self.log(f" Resposta recebida: {response[:100]}...")
                    
                    self.results['endpoints_tested'].append({
                        'endpoint': endpoint,
                        'uri': uri,
                        'status': 'success',
                        'response': response
                    })
                    self.results['successful_connections'] += 1
                    return True
                    
                except asyncio.TimeoutError:
                    self.log(f"⏰ Timeout aguardando resposta de {endpoint}")
                    self.results['endpoints_tested'].append({
                        'endpoint': endpoint,
                        'uri': uri,
                        'status': 'timeout',
                        'error': 'Response timeout'
                    })
                    self.results['failed_connections'] += 1
                    return False
                    
        except Exception as e:
            error_msg = str(e)
            self.log(f" Erro conectando a {endpoint}: {error_msg}")
            self.results['endpoints_tested'].append({
                'endpoint': endpoint,
                'uri': uri,
                'status': 'error',
                'error': error_msg
            })
            self.results['errors'].append({
                'endpoint': endpoint,
                'error': error_msg
            })
            self.results['failed_connections'] += 1
            return False
    
    async def run_websocket_tests(self):
        """Executa todos os testes de WebSocket"""
        self.log(" === INICIANDO TESTES DE WEBSOCKET ===\n")
        
        # Endpoints que devem estar disponíveis
        expected_endpoints = [
            "/ws",
            "/api/ws", 
            "/websocket",
            "/ws/test_node"  # Endpoint atual
        ]
        
        for endpoint in expected_endpoints:
            await self.test_websocket_endpoint(endpoint)
            await asyncio.sleep(0.5)  # Pequena pausa entre testes
        
        # Gera resumo dos resultados
        total_tests = len(expected_endpoints)
        success_rate = (self.results['successful_connections'] / total_tests) * 100 if total_tests > 0 else 0
        
        self.results['test_summary'] = {
            'total_endpoints_tested': total_tests,
            'successful_connections': self.results['successful_connections'],
            'failed_connections': self.results['failed_connections'],
            'success_rate': round(success_rate, 2),
            'timestamp': datetime.now().isoformat()
        }
        
        self.log(f"\n === RESUMO DOS TESTES DE WEBSOCKET ===")
        self.log(f"Total de endpoints testados: {total_tests}")
        self.log(f"Conexões bem-sucedidas: {self.results['successful_connections']}")
        self.log(f"Conexões falharam: {self.results['failed_connections']}")
        self.log(f"Taxa de sucesso: {success_rate:.1f}%")
        
        # Salva resultados detalhados
        with open('websocket_test_results.json', 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        self.log(f"\n Resultados salvos em: websocket_test_results.json")
        
        # Teste TDD: deve falhar se menos de 75% dos endpoints funcionarem
        if success_rate < 75:
            self.log(f"\n TESTE TDD FALHOU: Taxa de sucesso ({success_rate:.1f}%) abaixo do esperado (75%)")
            self.log(" Correções necessárias:")
            
            if self.results['failed_connections'] > 0:
                self.log("   - Implementar endpoints WebSocket faltantes")
                self.log("   - Corrigir problemas de conexão")
                self.log("   - Verificar configuração do servidor")
            
            return False
        else:
            self.log(f"\n TESTE TDD PASSOU: WebSockets funcionando adequadamente")
            return True

def main():
    """Função principal para executar os testes"""
    async def run_tests():
        test_suite = WebSocketTestSuite()
        success = await test_suite.run_websocket_tests()
        return success
    
    try:
        success = asyncio.run(run_tests())
        exit_code = 0 if success else 1
        print(f"\n Teste finalizado com código de saída: {exit_code}")
        exit(exit_code)
    except Exception as e:
        print(f"\n Erro fatal durante os testes: {e}")
        exit(2)

if __name__ == "__main__":
    main()