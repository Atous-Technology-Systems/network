"""
Testes de integração para o ABISSSystem

Este módulo contém testes de integração que verificam a interação entre os componentes
principais do sistema ABISS, incluindo ThreatPattern, AdaptiveResponse e ABISSSystem.
"""
import unittest
from unittest.mock import patch, MagicMock
import time
from typing import Dict, Any, List

from atous_sec_network.security.abiss_system import (
    ABISSSystem, 
    ThreatPattern, 
    AdaptiveResponse
)

class TestABISSIntegration(unittest.TestCase):
    """Testes de integração para o ABISSSystem"""
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        # Configuração básica para os testes
        self.config = {
            "model_name": "google/gemma-3n-2b",
            "simulation_mode": True,  # Usar modo simulação para testes
            "memory_size": 1000,
            "threat_threshold": 0.7,  # Threshold para detecção de ameaças
            "thresholds": {
                "threat_detection": 0.7,
                "behavior_anomaly": 0.6
            }
        }
        
        # Inicializa o sistema ABISS
        self.abiss_system = ABISSSystem(self.config)
        
        # Dados de exemplo para os testes
        self.sample_network_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "protocol": "tcp",
            "port": 80,
            "payload_size": 1024,
            "timestamp": int(time.time())
        }
        
        # Padrão de ameaça de exemplo
        self.sample_threat_pattern = {
            "pattern_type": "brute_force",
            "indicators": ["multiple_failed_logins", "rapid_requests"],
            "severity": 0.8,
            "frequency": 0.7,
            "description": "Padrão de tentativa de força bruta"
        }
    
    def tearDown(self):
        """Limpeza após cada teste"""
        if hasattr(self, 'abiss_system') and hasattr(self.abiss_system, 'stop_real_time_monitoring'):
            self.abiss_system.stop_real_time_monitoring()
    
    def test_threat_detection_with_learned_pattern(self):
        """
        Testa a detecção de ameaças com um padrão aprendido
        """
        # Aprender um novo padrão de ameaça
        pattern_id = self.abiss_system.learn_threat_pattern(self.sample_threat_pattern)
        self.assertIsNotNone(pattern_id)
        
        # Verificar se o padrão foi aprendido corretamente
        learned_pattern = self.abiss_system.get_threat_pattern(pattern_id)
        self.assertIsNotNone(learned_pattern)
        self.assertEqual(learned_pattern.pattern_type, "brute_force")
        
        # Dados que correspondem ao padrão aprendido
        test_data = {
            "event_type": "login_attempt",
            "status": "failed",
            "multiple_failed_logins": True,
            "rapid_requests": True,
            "user": "admin"
        }
        
        # Detectar ameaça
        threat_score, threat_type = self.abiss_system.detect_threat(test_data)
        
        # Verificar se o padrão foi detectado corretamente
        # O score pode variar, então verificamos se o tipo está correto
        self.assertIsInstance(threat_score, float)
        self.assertGreaterEqual(threat_score, 0.0)
        self.assertLessEqual(threat_score, 1.0)
        self.assertEqual(threat_type, "brute_force")
    
    def test_adaptive_response_generation_and_execution(self):
        """
        Testa a geração e execução de uma resposta adaptativa
        """
        # Detectar ameaça
        test_data = {
            "event_type": "port_scan",
            "source_ip": "192.168.1.100",
            "ports_scanned": [22, 80, 443, 3389],
            "timestamp": int(time.time())
        }
        
        threat_score, threat_type = self.abiss_system.detect_threat(test_data)
        self.assertGreaterEqual(threat_score, 0.0)
        
        # Gerar resposta adaptativa
        response = self.abiss_system.generate_adaptive_response({
            "threat_score": threat_score,
            "threat_type": threat_type,
            "source_ip": "192.168.1.100"
        })
        
        # Verificar se a resposta foi gerada corretamente
        self.assertIsNotNone(response)
        self.assertIn(response.action, ["block_ip", "rate_limit", "alert_admin", "monitor"])
        
        # Executar a resposta
        result = response.execute()
        self.assertTrue(result["success"])
    
    @patch('atous_sec_network.security.abiss_system.TRANSFORMERS_AVAILABLE', False)
    def test_initialization_without_transformers(self):
        """
        Testa a inicialização do sistema sem a biblioteca transformers
        """
        # Deve ser possível inicializar mesmo sem a biblioteca transformers
        abiss = ABISSSystem({"simulation_mode": True})
        self.assertIsNotNone(abiss)
        
        # A detecção de ameaças deve funcionar em modo simulação
        threat_score, threat_type = abiss.detect_threat({"event_type": "test"})
        self.assertIsInstance(threat_score, float)
        self.assertIsInstance(threat_type, str)
    
    def test_behavior_analysis_integration(self):
        """
        Testa a integração da análise comportamental
        """
        # Dados comportamentais de exemplo
        behavior_data = {
            "user_id": "user123",
            "login_time": "09:30",
            "resources_accessed": ["file1.txt", "file2.txt"],
            "network_usage_mb": 5.2,
            "failed_attempts": 0
        }
        
        # Analisar comportamento
        score, anomalies = self.abiss_system.analyze_behavior(behavior_data)
        
        # Verificar resultados
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)
        self.assertIsInstance(anomalies, list)
    
    def test_real_time_monitoring_integration(self):
        """
        Testa a integração do monitoramento em tempo real
        """
        # Iniciar monitoramento
        self.abiss_system.start_real_time_monitoring()
        self.assertTrue(self.abiss_system.is_monitoring)
        
        # Processar alguns dados em tempo real
        alerts = self.abiss_system.process_real_time_data({
            "event_type": "suspicious_activity",
            "source_ip": "10.0.0.100",
            "description": "Tentativa de acesso a recurso restrito"
        })
        
        # Verificar se os alertas foram gerados
        self.assertIsInstance(alerts, list)
        
        # Parar monitoramento
        self.abiss_system.stop_real_time_monitoring()
        self.assertFalse(self.abiss_system.is_monitoring)


if __name__ == '__main__':
    unittest.main()
