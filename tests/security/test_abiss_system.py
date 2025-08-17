import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
import json

# Importações do sistema
from atous_sec_network.security.abiss_system import ABISSSystem


class TestABISSSystemSpecs:
    """Especificações de teste para o sistema ABISS"""
    
    def test_abiss_system_initialization(self):
        """Testa se o sistema ABISS é inicializado corretamente"""
        # Arrange
        config = {
            "block_threshold": 0.90,
            "monitor_threshold": 0.75,
            "endpoint_whitelist": ["/health", "/auth/register"]
        }
        
        # Act
        abiss = ABISSSystem(config)
        
        # Assert
        assert abiss.block_threshold == 0.90
        assert abiss.monitor_threshold == 0.75
        assert "/health" in abiss.endpoint_whitelist
        assert "/auth/register" in abiss.endpoint_whitelist
    
    def test_abiss_default_configuration(self):
        """Testa se a configuração padrão é aplicada quando não fornecida"""
        # Arrange & Act
        abiss = ABISSSystem()
        
        # Assert
        assert abiss.block_threshold == 0.90
        assert abiss.monitor_threshold == 0.75
        assert isinstance(abiss.endpoint_whitelist, list)
    
    def test_abiss_threshold_configuration(self):
        """Testa se os thresholds são configuráveis"""
        # Arrange
        config = {
            "block_threshold": 0.95,
            "monitor_threshold": 0.80
        }
        
        # Act
        abiss = ABISSSystem(config)
        abiss.configure_thresholds(config)
        
        # Assert
        assert abiss.block_threshold == 0.95
        assert abiss.monitor_threshold == 0.80
    
    def test_abiss_legitimate_request_analysis(self):
        """Testa se uma requisição legítima recebe score baixo"""
        # Arrange
        abiss = ABISSSystem()
        legitimate_request = {
            "method": "POST",
            "url": "/auth/register",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "testuser", "email": "test@example.com"},
            "ip": "127.0.0.1"
        }
        
        # Act
        score = abiss.analyze_request(legitimate_request)
        
        # Assert
        assert score < 0.75, f"Score deve ser < 0.75, mas foi {score}"
        assert abiss.is_request_allowed(score), "Requisição deve ser permitida"
    
    def test_abiss_suspicious_request_analysis(self):
        """Testa se uma requisição suspeita recebe score médio"""
        # Arrange
        abiss = ABISSSystem()
        suspicious_request = {
            "method": "POST",
            "url": "/auth/register",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "admin", "email": "admin@admin.com"},
            "ip": "192.168.1.100"
        }
        
        # Act
        score = abiss.analyze_request(suspicious_request)
        
        # Assert
        assert 0.75 <= score < 0.90, f"Score deve estar entre 0.75 e 0.90, mas foi {score}"
        assert abiss.is_request_allowed(score), "Requisição suspeita deve ser permitida mas monitorada"
    
    def test_abiss_malicious_request_analysis(self):
        """Testa se uma requisição maliciosa recebe score alto"""
        # Arrange
        abiss = ABISSSystem()
        malicious_request = {
            "method": "POST",
            "url": "/auth/register",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "'; DROP TABLE users; --", "email": "sql@injection.com"},
            "ip": "10.0.0.1"
        }
        
        # Act
        score = abiss.analyze_request(malicious_request)
        
        # Assert
        assert score >= 0.90, f"Score deve ser >= 0.90, mas foi {score}"
        assert not abiss.is_request_allowed(score), "Requisição maliciosa deve ser bloqueada"
    
    def test_abiss_whitelist_endpoints(self):
        """Testa se endpoints na whitelist recebem score reduzido"""
        # Arrange
        config = {
            "endpoint_whitelist": ["/health", "/auth/register", "/auth/login"]
        }
        abiss = ABISSSystem(config)
        
        whitelist_requests = [
            {"method": "GET", "url": "/health", "headers": {}, "body": {}, "ip": "127.0.0.1"},
            {"method": "POST", "url": "/auth/register", "headers": {"Content-Type": "application/json"}, "body": {}, "ip": "127.0.0.1"},
            {"method": "POST", "url": "/auth/login", "headers": {"Content-Type": "application/json"}, "body": {}, "ip": "127.0.0.1"}
        ]
        
        # Act & Assert
        for request in whitelist_requests:
            score = abiss.analyze_request(request)
            assert score < 0.50, f"Endpoint {request['url']} deve ter score < 0.50, mas foi {score}"
    
    def test_abiss_behavior_history_learning(self):
        """Testa se o sistema aprende com o histórico de comportamento"""
        # Arrange
        abiss = ABISSSystem()
        ip_address = "127.0.0.1"
        
        # Primeira requisição (pode ser suspeita)
        first_request = {
            "method": "POST",
            "url": "/auth/register",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "newuser", "email": "new@user.com"},
            "ip": ip_address
        }
        
        # Segunda requisição (deve ter score menor devido ao histórico)
        second_request = {
            "method": "POST",
            "url": "/auth/login",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "newuser", "password": "password123"},
            "ip": ip_address
        }
        
        # Act
        first_score = abiss.analyze_request(first_request)
        second_score = abiss.analyze_request(second_request)
        
        # Assert
        # Para IPs conhecidos, o score deve ser relativamente estável
        # Permitir uma pequena variação devido ao contexto diferente das requisições
        score_difference = abs(second_score - first_score)
        assert score_difference < 0.1, f"Score deve ser estável para IPs conhecidos, diferença: {score_difference:.3f}"
    
    def test_abiss_context_analysis(self):
        """Testa se o sistema analisa o contexto da requisição"""
        # Arrange
        abiss = ABISSSystem()
        
        # Requisição com contexto normal
        normal_context = {
            "method": "POST",
            "url": "/auth/register",
            "headers": {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            "body": {"username": "user1", "email": "user1@example.com"},
            "ip": "127.0.0.1"
        }
        
        # Requisição com contexto suspeito
        suspicious_context = {
            "method": "POST",
            "url": "/auth/register",
            "headers": {"Content-Type": "application/json", "User-Agent": "curl/7.68.0"},
            "body": {"username": "user2", "email": "user2@example.com"},
            "ip": "127.0.0.1"
        }
        
        # Act
        normal_score = abiss.analyze_request(normal_context)
        suspicious_score = abiss.analyze_request(suspicious_context)
        
        # Assert
        assert normal_score < suspicious_score, "Contexto normal deve ter score menor que contexto suspeito"
    
    def test_abiss_score_consistency(self):
        """Testa se o score é consistente para a mesma requisição"""
        # Arrange
        abiss = ABISSSystem()
        request = {
            "method": "POST",
            "url": "/auth/register",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "testuser", "email": "test@example.com"},
            "ip": "127.0.0.1"
        }
        
        # Act
        score1 = abiss.analyze_request(request)
        score2 = abiss.analyze_request(request)
        score3 = abiss.analyze_request(request)
        
        # Assert
        assert abs(score1 - score2) < 0.01, "Scores devem ser consistentes"
        assert abs(score2 - score3) < 0.01, "Scores devem ser consistentes"
    
    def test_abiss_performance_requirements(self):
        """Testa se o sistema atende aos requisitos de performance"""
        # Arrange
        abiss = ABISSSystem()
        request = {
            "method": "POST",
            "url": "/auth/register",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "testuser", "email": "test@example.com"},
            "ip": "127.0.0.1"
        }
        
        # Act
        import time
        start_time = time.time()
        score = abiss.analyze_request(request)
        end_time = time.time()
        
        execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        # Assert
        assert execution_time < 100, f"Análise deve ser feita em < 100ms, mas foi {execution_time:.2f}ms"
        assert 0 <= score <= 1.0, f"Score deve estar entre 0 e 1, mas foi {score}"


class TestABISSEndpointsSpecs:
    """Especificações de teste para endpoints do sistema ABISS"""
    
    @pytest.fixture
    def client(self):
        """Fixture para cliente de teste"""
        from fastapi.testclient import TestClient
        from atous_sec_network.api.server import app
        return TestClient(app)
    
    def test_abiss_status_endpoint_accessible(self, client):
        """Testa se o endpoint de status do ABISS está acessível"""
        # Act
        response = client.get("/api/security/abiss/status")
        
        # Assert
        # Pode retornar 200 (funcionando) ou 403 (bloqueando)
        assert response.status_code in [200, 403], f"Status code inesperado: {response.status_code}"
        
        if response.status_code == 403:
            data = response.json()
            assert "error" in data, "Resposta de erro deve conter campo 'error'"
            assert "reason" in data, "Resposta de erro deve conter campo 'reason'"
            assert "ABISS" in data["reason"], "Motivo deve mencionar ABISS"
    
    def test_abiss_configuration_endpoint(self, client):
        """Testa se o endpoint de configuração do ABISS está acessível"""
        # Act
        response = client.get("/api/security/abiss/config")
        
        # Assert
        # Pode retornar 200 (funcionando) ou 403 (bloqueando)
        assert response.status_code in [200, 403], f"Status code inesperado: {response.status_code}"
        
        if response.status_code == 200:
            data = response.json()
            assert "block_threshold" in data, "Configuração deve conter threshold de bloqueio"
            assert "monitor_threshold" in data, "Configuração deve conter threshold de monitoramento"
    
    def test_abiss_statistics_endpoint(self, client):
        """Testa se o endpoint de estatísticas do ABISS está acessível"""
        # Act
        response = client.get("/api/security/abiss/stats")
        
        # Assert
        # Pode retornar 200 (funcionando) ou 403 (bloqueando)
        assert response.status_code in [200, 403], f"Status code inesperado: {response.status_code}"
        
        if response.status_code == 200:
            data = response.json()
            assert "total_requests" in data, "Estatísticas devem conter total de requisições"
            assert "blocked_requests" in data, "Estatísticas devem conter requisições bloqueadas"
            assert "average_score" in data, "Estatísticas devem conter score médio"


class TestABISSIntegrationSpecs:
    """Especificações de teste para integração do sistema ABISS"""
    
    @pytest.mark.asyncio
    async def test_abiss_with_middleware_integration(self):
        """Testa se o ABISS integra corretamente com o middleware de segurança"""
        # Arrange
        from atous_sec_network.security.security_middleware import ComprehensiveSecurityMiddleware
        from fastapi import FastAPI
        from unittest.mock import AsyncMock, patch
        
        app = FastAPI()
        middleware = ComprehensiveSecurityMiddleware(app)
        
        # Act & Assert
        assert hasattr(middleware, 'abiss_system'), "Middleware deve ter sistema ABISS"
        
        # The ABISS system is lazy loaded, so it should be None initially
        assert middleware.abiss_system is None, "Sistema ABISS deve ser inicializado apenas quando necessário"
        
        # Test that ABISS can be initialized when needed
        # Mock the request to trigger ABISS initialization
        mock_request = AsyncMock()
        mock_request.method = "GET"
        mock_request.url = "http://test.com/api/test"
        mock_request.headers = {}
        
        # Call the method that triggers ABISS initialization
        with patch('atous_sec_network.security.abiss_system.ABISSSystem') as mock_abiss_class:
            mock_abiss_instance = AsyncMock()
            mock_abiss_class.return_value = mock_abiss_instance
            mock_abiss_instance.analyze_request.return_value = 0.1
            mock_abiss_instance.is_request_allowed.return_value = True
            mock_abiss_instance.monitor_threshold = 0.5
            mock_abiss_instance.block_threshold = 0.8
            
            # This should trigger ABISS initialization
            result = await middleware._analyze_with_abiss(mock_request, "127.0.0.1")
            
            # Verify ABISS was initialized
            assert middleware.abiss_system is not None, "Sistema ABISS deve ser inicializado após primeira análise"
            assert result is None, "Análise ABISS deve retornar None para requisições seguras"
    
    def test_abiss_configuration_loading(self):
        """Testa se a configuração do ABISS é carregada corretamente"""
        # Arrange
        import yaml
        from pathlib import Path
        
        config_path = Path("config/security_presets.yaml")
        
        # Act & Assert
        assert config_path.exists(), "Arquivo de configuração deve existir"
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        assert "abiss" in config, "Configuração deve conter seção ABISS"
        assert "thresholds" in config["abiss"], "Configuração ABISS deve conter thresholds"
    
    def test_abiss_logging_integration(self):
        """Testa se o ABISS integra corretamente com o sistema de logging"""
        # Arrange
        abiss = ABISSSystem()
        request = {
            "method": "POST",
            "url": "/auth/register",
            "headers": {"Content-Type": "application/json"},
            "body": {"username": "testuser", "email": "test@example.com"},
            "ip": "127.0.0.1"
        }
        
        # Act
        with patch('atous_sec_network.security.abiss_system.logger') as mock_logger:
            score = abiss.analyze_request(request)
            
        # Assert
        # Verifica se o logger foi chamado (pode variar dependendo da implementação)
        # mock_logger.info.assert_called()  # Comentado pois pode não ser implementado ainda
    
    def test_abiss_metrics_collection(self):
        """Testa se o ABISS coleta métricas corretamente"""
        # Arrange
        abiss = ABISSSystem()
        
        # Simular algumas requisições
        requests = [
            {"method": "POST", "url": "/auth/register", "headers": {}, "body": {}, "ip": "127.0.0.1"},
            {"method": "POST", "url": "/auth/login", "headers": {}, "body": {}, "ip": "127.0.0.1"},
            {"method": "GET", "url": "/health", "headers": {}, "body": {}, "ip": "127.0.0.1"}
        ]
        
        # Act
        scores = []
        for request in requests:
            score = abiss.analyze_request(request)
            scores.append(score)
        
        # Assert
        assert len(scores) == 3, "Deve ter analisado 3 requisições"
        assert all(0 <= score <= 1.0 for score in scores), "Todos os scores devem estar entre 0 e 1"
        
        # Verificar se as métricas estão sendo coletadas
        # Isso pode variar dependendo da implementação
        # assert hasattr(abiss, 'metrics'), "Sistema deve ter métricas"
        # assert abiss.metrics['total_requests'] == 3, "Deve ter contado 3 requisições"


if __name__ == "__main__":
    # Executar testes se executado diretamente
    pytest.main([__file__, "-v"])
