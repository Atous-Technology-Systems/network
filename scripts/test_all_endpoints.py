#!/usr/bin/env python3
"""
Teste Completo de Todos os Endpoints da ATous Secure Network
"""

import requests
import json
import time
from typing import Dict, List, Any

class NetworkTester:
    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = {}
        
    def test_endpoint(self, method: str, endpoint: str, expected_status: int = 200, **kwargs) -> Dict[str, Any]:
        """Testa um endpoint específico"""
        url = f"{self.base_url}{endpoint}"
        try:
            if method.upper() == "GET":
                response = self.session.get(url, timeout=10, **kwargs)
            elif method.upper() == "POST":
                response = self.session.post(url, timeout=10, **kwargs)
            elif method.upper() == "PUT":
                response = self.session.put(url, timeout=10, **kwargs)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, timeout=10, **kwargs)
            else:
                return {"error": f"Método {method} não suportado"}
            
            result = {
                "status_code": response.status_code,
                "success": response.status_code == expected_status,
                "response_time": response.elapsed.total_seconds(),
                "content_type": response.headers.get("content-type", ""),
                "content_length": len(response.content)
            }
            
            if response.status_code == 200:
                try:
                    result["data"] = response.json()
                except:
                    result["data"] = response.text[:200]
            
            return result
            
        except requests.exceptions.ConnectionError:
            return {"error": "Servidor não está rodando"}
        except requests.exceptions.Timeout:
            return {"error": "Timeout na requisição"}
        except Exception as e:
            return {"error": f"Erro: {str(e)}"}
    
    def test_all_endpoints(self) -> Dict[str, Any]:
        """Testa todos os endpoints principais"""
        print("🚀 Testando Todos os Endpoints da ATous Secure Network")
        print("=" * 60)
        
        # Endpoints básicos
        basic_endpoints = [
            ("GET", "/", "Página principal"),
            ("GET", "/health", "Health check"),
            ("GET", "/docs", "Documentação Swagger"),
            ("GET", "/openapi.json", "Schema OpenAPI"),
            ("GET", "/api/security/status", "Status de segurança"),
        ]
        
        print("\n📡 Testando Endpoints Básicos:")
        for method, endpoint, description in basic_endpoints:
            print(f"\n🔍 {description} ({method} {endpoint})")
            result = self.test_endpoint(method, endpoint)
            self.results[f"{method}_{endpoint}"] = result
            
            if "error" in result:
                print(f"   ❌ {result['error']}")
            else:
                status_icon = "✅" if result["success"] else "⚠️"
                print(f"   {status_icon} Status: {result['status_code']} | Tempo: {result['response_time']:.3f}s")
        
        # Endpoints de segurança
        security_endpoints = [
            ("GET", "/api/security/abiss/status", "Status ABISS"),
            ("GET", "/api/security/nnis/status", "Status NNIS"),
            ("GET", "/api/security/keys", "Gerenciamento de chaves"),
            ("POST", "/api/security/analyze", "Análise de segurança"),
        ]
        
        print("\n🔒 Testando Endpoints de Segurança:")
        for method, endpoint, description in security_endpoints:
            print(f"\n🔍 {description} ({method} {endpoint})")
            result = self.test_endpoint(method, endpoint)
            self.results[f"{method}_{endpoint}"] = result
            
            if "error" in result:
                print(f"   ❌ {result['error']}")
            else:
                status_icon = "✅" if result["success"] else "⚠️"
                print(f"   {status_icon} Status: {result['status_code']} | Tempo: {result['response_time']:.3f}s")
        
        # Endpoints de autenticação
        auth_endpoints = [
            ("POST", "/api/auth/register", "Registro de usuário"),
            ("POST", "/api/auth/login", "Login"),
            ("POST", "/api/auth/refresh", "Refresh token"),
            ("GET", "/api/auth/profile", "Perfil do usuário"),
        ]
        
        print("\n🔐 Testando Endpoints de Autenticação:")
        for method, endpoint, description in auth_endpoints:
            print(f"\n🔍 {description} ({method} {endpoint})")
            result = self.test_endpoint(method, endpoint)
            self.results[f"{method}_{endpoint}"] = result
            
            if "error" in result:
                print(f"   ❌ {result['error']}")
            else:
                status_icon = "✅" if result["success"] else "⚠️"
                print(f"   {status_icon} Status: {result['status_code']} | Tempo: {result['response_time']:.3f}s")
        
        # Endpoints de overlay
        overlay_endpoints = [
            ("GET", "/api/overlay/discovery", "Descoberta de serviços"),
            ("POST", "/api/overlay/enroll", "Enrolamento"),
            ("POST", "/api/overlay/heartbeat", "Heartbeat"),
            ("GET", "/api/overlay/policies/active", "Políticas ativas"),
            ("POST", "/api/overlay/relay", "Relay"),
        ]
        
        print("\n🌐 Testando Endpoints de Overlay:")
        for method, endpoint, description in overlay_endpoints:
            print(f"\n🔍 {description} ({method} {endpoint})")
            result = self.test_endpoint(method, endpoint)
            self.results[f"{method}_{endpoint}"] = result
            
            if "error" in result:
                print(f"   ❌ {result['error']}")
            else:
                status_icon = "✅" if result["success"] else "⚠️"
                print(f"   {status_icon} Status: {result['status_code']} | Tempo: {result['response_time']:.3f}s")
        
        # Endpoints de admin
        admin_endpoints = [
            ("GET", "/api/admin/overview", "Visão geral admin"),
            ("GET", "/api/admin/events", "Eventos admin"),
            ("GET", "/api/admin/agents", "Agentes"),
            ("GET", "/api/admin/policies", "Políticas"),
        ]
        
        print("\n👑 Testando Endpoints de Admin:")
        for method, endpoint, description in admin_endpoints:
            print(f"\n🔍 {description} ({method} {endpoint})")
            result = self.test_endpoint(method, endpoint)
            self.results[f"{method}_{endpoint}"] = result
            
            if "error" in result:
                print(f"   ❌ {result['error']}")
            else:
                status_icon = "✅" if result["success"] else "⚠️"
                print(f"   {status_icon} Status: {result['status_code']} | Tempo: {result['response_time']:.3f}s")
        
        return self.results
    
    def generate_report(self) -> str:
        """Gera um relatório dos testes"""
        total_tests = len(self.results)
        successful_tests = sum(1 for r in self.results.values() if "error" not in r and r.get("success", False))
        failed_tests = sum(1 for r in self.results.values() if "error" in r or not r.get("success", False))
        
        report = f"""
📊 RELATÓRIO COMPLETO DOS TESTES
{'=' * 50}
🎯 Total de Endpoints Testados: {total_tests}
✅ Endpoints Funcionando: {successful_tests}
❌ Endpoints com Problemas: {failed_tests}
📈 Taxa de Sucesso: {(successful_tests/total_tests*100):.1f}%

🔍 DETALHES DOS TESTES:
"""
        
        for endpoint, result in self.results.items():
            if "error" in result:
                report += f"\n❌ {endpoint}: {result['error']}"
            else:
                status_icon = "✅" if result["success"] else "⚠️"
                report += f"\n{status_icon} {endpoint}: Status {result['status_code']} | {result['response_time']:.3f}s"
        
        return report

def main():
    """Função principal"""
    print("🚀 ATous Secure Network - Teste Completo de Endpoints")
    print("=" * 60)
    
    # Aguardar servidor inicializar
    print("⏳ Aguardando servidor inicializar...")
    time.sleep(3)
    
    tester = NetworkTester()
    results = tester.test_all_endpoints()
    
    print("\n" + "=" * 60)
    print(tester.generate_report())
    
    # Salvar resultados
    with open("endpoints_test_report.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n💾 Relatório salvo em: endpoints_test_report.json")

if __name__ == "__main__":
    main()
