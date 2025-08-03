#!/usr/bin/env python3
"""
Testes para o Sistema de Treinamento OWASP

Testes abrangentes para verificar detecção e bloqueio de todos os ataques OWASP Top 10 2021.
"""

import pytest
import json
import time
from unittest.mock import Mock, MagicMock
from typing import Dict, List, Any

import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'scripts'))
from owasp_training_system import OWASPTrainingSystem, OWASPAttackPattern
from atous_sec_network.security.abiss_system import ThreatPattern


class TestOWASPAttackPattern:
    """Testes para a classe OWASPAttackPattern"""
    
    def test_owasp_attack_pattern_creation(self):
        """Testa criação de padrão de ataque OWASP"""
        pattern = OWASPAttackPattern(
            owasp_id="A01",
            name="Test Attack",
            description="Test description",
            indicators=["test_indicator"],
            severity=8.0,
            detection_rules=[{"type": "test", "pattern": "test_pattern"}],
            mitigation_strategies=["test_mitigation"],
            test_payloads=["test_payload"]
        )
        
        assert pattern.owasp_id == "A01"
        assert pattern.name == "Test Attack"
        assert pattern.description == "Test description"
        assert pattern.indicators == ["test_indicator"]
        assert pattern.severity == 8.0
        assert pattern.detection_rules == [{"type": "test", "pattern": "test_pattern"}]
        assert pattern.mitigation_strategies == ["test_mitigation"]
        assert pattern.test_payloads == ["test_payload"]


class TestOWASPTrainingSystem:
    """Testes para o sistema de treinamento OWASP"""
    
    @pytest.fixture
    def mock_abiss(self):
        """Mock do sistema ABISS"""
        mock = Mock()
        mock.add_threat_pattern.return_value = True
        mock.learn_threat_pattern.return_value = "pattern_123"
        mock.detect_threat.return_value = {
            'threat_detected': False,  # Deixar ABISS como não detectado para testar detecção local
            'confidence': 0.1,
            'patterns': []
        }
        return mock
    
    @pytest.fixture
    def mock_nnis(self):
        """Mock do sistema NNIS"""
        mock = Mock()
        mock.analyze_network_pattern.return_value = {
            'anomaly_detected': False,  # Deixar NNIS como não detectado para testar detecção local
            'confidence': 0.1
        }
        return mock
    
    @pytest.fixture
    def training_system(self, mock_abiss, mock_nnis):
        """Sistema de treinamento para testes"""
        return OWASPTrainingSystem(mock_abiss, mock_nnis)
    
    def test_initialization(self, training_system):
        """Testa inicialização do sistema"""
        assert training_system.abiss is not None
        assert training_system.nnis is not None
        assert training_system.logger is not None
        assert len(training_system.owasp_patterns) == 10
        assert training_system.training_stats["patterns_trained"] == 0
        assert training_system.training_stats["detection_accuracy"] == 0.0
        assert training_system.training_stats["false_positive_rate"] == 0.0
        assert training_system.training_stats["training_sessions"] == 0
    
    def test_owasp_patterns_initialization(self, training_system):
        """Testa inicialização dos padrões OWASP Top 10"""
        patterns = training_system.owasp_patterns
        
        # Verificar se todos os 10 padrões estão presentes
        expected_patterns = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]
        for pattern_id in expected_patterns:
            assert pattern_id in patterns
            pattern = patterns[pattern_id]
            assert pattern.owasp_id == pattern_id
            assert pattern.name is not None
            assert pattern.description is not None
            assert len(pattern.indicators) > 0
            assert pattern.severity > 0
            assert len(pattern.detection_rules) > 0
            assert len(pattern.mitigation_strategies) > 0
            assert len(pattern.test_payloads) > 0
    
    def test_specific_owasp_patterns(self, training_system):
        """Testa padrões específicos do OWASP"""
        patterns = training_system.owasp_patterns
        
        # A01 - Broken Access Control
        a01 = patterns["A01"]
        assert a01.name == "Broken Access Control"
        assert a01.severity == 9.0
        assert "../../../etc/passwd" in a01.test_payloads
        
        # A03 - Injection
        a03 = patterns["A03"]
        assert a03.name == "Injection"
        assert a03.severity == 9.5
        assert "' OR '1'='1" in a03.test_payloads
        
        # A10 - SSRF
        a10 = patterns["A10"]
        assert a10.name == "Server-Side Request Forgery (SSRF)"
        assert a10.severity == 8.0
        assert "url=http://localhost:22" in a10.test_payloads
    
    def test_train_pattern_success(self, training_system, mock_abiss):
        """Testa treinamento bem-sucedido de um padrão"""
        result = training_system.train_pattern("A01")
        
        assert result is True
        assert training_system.training_stats["patterns_trained"] == 1
        mock_abiss.learn_threat_pattern.assert_called_once()
        
        # Verificar se o dicionário de dados foi criado corretamente
        call_args = mock_abiss.learn_threat_pattern.call_args[0][0]
        assert call_args["pattern_id"] == "owasp_a01"
        assert "broken_access_control" in call_args["pattern_type"]
        assert call_args["severity"] > 0
    
    def test_train_pattern_failure(self, training_system, mock_abiss):
        """Testa falha no treinamento de um padrão"""
        mock_abiss.learn_threat_pattern.return_value = None
        
        result = training_system.train_pattern("A01")
        
        assert result is False
        assert training_system.training_stats["patterns_trained"] == 0
    
    def test_train_pattern_invalid_id(self, training_system):
        """Testa treinamento com ID inválido"""
        result = training_system.train_pattern("INVALID")
        
        assert result is False
        assert training_system.training_stats["patterns_trained"] == 0
    
    def test_train_all_patterns(self, training_system, mock_abiss):
        """Testa treinamento de todos os padrões"""
        results = training_system.train_all_patterns()
        
        assert len(results) == 10
        assert all(results.values())  # Todos devem ser True
        assert training_system.training_stats["patterns_trained"] == 10
        assert training_system.training_stats["training_sessions"] == 1
        assert training_system.training_stats["detection_accuracy"] == 100.0
        assert mock_abiss.learn_threat_pattern.call_count == 10
    
    def test_matches_rule_regex(self, training_system):
        """Testa correspondência de regras com regex"""
        rule = {"type": "sql_injection", "pattern": r"'|\"|/\*|\*/|;|--|\bunion\b|\bselect\b"}
        
        # Testes positivos
        assert training_system._matches_rule("' OR 1=1", rule) is True
        assert training_system._matches_rule('" OR 1=1', rule) is True
        assert training_system._matches_rule("SELECT * FROM users", rule) is True
        assert training_system._matches_rule("UNION SELECT", rule) is True
        assert training_system._matches_rule("/* comment */", rule) is True
        assert training_system._matches_rule("admin'--", rule) is True
        
        # Testes negativos
        assert training_system._matches_rule("normal text", rule) is False
        assert training_system._matches_rule("user@example.com", rule) is False
    
    def test_matches_rule_simple_pattern(self, training_system):
        """Testa correspondência de regras com padrão simples"""
        rule = {"type": "test", "pattern": "admin"}
        
        assert training_system._matches_rule("admin:admin", rule) is True
        assert training_system._matches_rule("ADMIN:password", rule) is True
        assert training_system._matches_rule("user:password", rule) is False
    
    def test_detect_attack_sql_injection(self, training_system):
        """Testa detecção de SQL Injection"""
        test_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "admin'--",
            "1 UNION SELECT password FROM users"
        ]
        
        for payload in test_payloads:
            result = training_system.detect_attack(payload)
            assert result['attack_detected'] is True
            assert any("A03" in attack for attack in result.get('owasp_attacks', []))
    
    def test_detect_attack_xss(self, training_system):
        """Testa detecção de XSS"""
        test_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "vbscript:msgbox('XSS')"
        ]
        
        for payload in test_payloads:
            result = training_system.detect_attack(payload)
            assert result['attack_detected'] is True
            assert any("A03" in attack for attack in result.get('owasp_attacks', []))
    
    def test_detect_attack_path_traversal(self, training_system):
        """Testa detecção de Path Traversal"""
        test_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd"
        ]
        
        for payload in test_payloads:
            result = training_system.detect_attack(payload)
            assert result['attack_detected'] is True
            assert any("A01" in attack for attack in result.get('owasp_attacks', []))
    
    def test_detect_attack_ssrf(self, training_system):
        """Testa detecção de SSRF"""
        test_payloads = [
            "http://localhost:22",
            "http://127.0.0.1:8080",
            "http://192.168.1.1/admin",
            "http://169.254.169.254/metadata",
            "file:///etc/passwd"
        ]
        
        for payload in test_payloads:
            result = training_system.detect_attack(payload)
            assert result['attack_detected'] is True
            assert any("A10" in attack for attack in result.get('owasp_attacks', []))
    
    def test_detect_attack_weak_credentials(self, training_system):
        """Testa detecção de credenciais fracas"""
        test_payloads = [
            "admin:admin",
            "root:password",
            "guest:guest",
            "password=123456"
        ]
        
        for payload in test_payloads:
            result = training_system.detect_attack(payload)
            assert result['attack_detected'] is True
            # Pode ser detectado como A05 (Security Misconfiguration) ou A07 (Auth Failures)
            owasp_attacks = result.get('owasp_attacks', [])
            assert any("A05" in attack or "A07" in attack for attack in owasp_attacks)
    
    def test_detect_attack_clean_data(self, training_system):
        """Testa que dados limpos não são detectados como ataques"""
        clean_payloads = [
            "user@example.com",
            "normal text input",
            "valid_username",
            "hello world"
        ]
        
        for payload in clean_payloads:
            result = training_system.detect_attack(payload)
            # Com os mocks configurados para não detectar, dados limpos não devem ser detectados
            assert result['attack_detected'] is False
            assert len(result.get('owasp_attacks', [])) == 0
    
    def test_block_attack(self, training_system):
        """Testa bloqueio de ataques"""
        attack_data = "' OR '1'='1"
        attack_info = {
            'attack_detected': True,
            'detected_patterns': ['sql_injection'],
            'owasp_attacks': ['A03: Injection'],
            'confidence': 0.9,
            'severity': 0.8
        }
        
        result = training_system.block_attack(attack_data, attack_info)
        
        assert result["blocked"] is True
        assert "A03: Injection" in result["owasp_attacks"]
        assert "mitigation_applied" in result
        assert len(result["mitigation_applied"]) > 0
    
    def test_get_training_report(self, training_system):
        """Testa geração de relatório de treinamento"""
        # Treinar alguns padrões primeiro
        training_system.train_pattern("A01")
        training_system.train_pattern("A03")
        
        report = training_system.get_training_report()
        
        assert report["owasp_version"] == "Top 10 2021"
        assert report["total_patterns"] == 10
        assert report["training_stats"]["patterns_trained"] == 2
        assert "patterns_details" in report
        assert len(report["patterns_details"]) == 10
        
        # Verificar detalhes de um padrão
        a01_details = report["patterns_details"]["A01"]
        assert a01_details["name"] == "Broken Access Control"
        assert a01_details["severity"] == 9.0
        assert a01_details["indicators_count"] > 0
        assert a01_details["test_payloads_count"] > 0
    
    def test_test_detection_capabilities(self, training_system):
        """Testa capacidades de detecção com payloads conhecidos"""
        results = training_system.test_detection_capabilities()
        
        assert "total_tests" in results
        assert "successful_detections" in results
        assert "failed_detections" in results
        assert "pattern_results" in results
        assert "success_rate" in results
        
        assert results["total_tests"] > 0
        assert len(results["pattern_results"]) == 10
        
        # Verificar resultados por padrão
        for pattern_id, pattern_result in results["pattern_results"].items():
            assert "tested_payloads" in pattern_result
            assert "detected" in pattern_result
            assert "missed" in pattern_result
            assert pattern_result["tested_payloads"] > 0
    
    def test_calculate_training_metrics(self, training_system):
        """Testa cálculo de métricas de treinamento"""
        # Treinar alguns padrões
        training_system.train_pattern("A01")
        training_system.train_pattern("A03")
        training_system.train_pattern("A10")
        
        training_system._calculate_training_metrics()
        
        assert training_system.training_stats["detection_accuracy"] == 30.0  # 3/10 * 100
        assert training_system.training_stats["false_positive_rate"] >= 0
    
    def test_comprehensive_attack_detection(self, training_system):
        """Teste abrangente de detecção de todos os tipos de ataque OWASP"""
        # Mapeamento de ataques por categoria OWASP
        attack_samples = {
            "A01": ["../../../etc/passwd", "admin=true", "role=administrator"],
            "A02": ["password=123456", "api_key=abc123", "token=plaintext_token"],
            "A03": ["' OR '1'='1", "<script>alert('XSS')</script>", "$(cat /etc/passwd)"],
            "A04": ["bypass_security=true", "skip_validation=1", "debug=true"],
            "A05": ["admin:admin", "root:password", "guest:guest"],
            "A06": ["version=1.0.0", "library=vulnerable_lib", "component=outdated"],
            "A07": ["password=123456", "password=password", "session_id=fixed_value"],
            "A08": ["update=unsigned", "data=serialized_object", "plugin=untrusted"],
            "A09": ["action=silent", "log=disabled", "monitor=off"],
            "A10": ["url=http://localhost:22", "url=http://169.254.169.254/", "url=file:///etc/passwd"]
        }
        
        detection_results = {}
        
        for owasp_id, attacks in attack_samples.items():
            detection_results[owasp_id] = []
            for attack in attacks:
                result = training_system.detect_attack(attack)
                detection_results[owasp_id].append({
                    "attack": attack,
                    "detected": result['attack_detected'],
                    "types": result.get('owasp_attacks', [])
                })
        
        # Verificar se pelo menos um ataque de cada categoria foi detectado
        for owasp_id, results in detection_results.items():
            detected_count = sum(1 for r in results if r["detected"])
            assert detected_count > 0, f"Nenhum ataque {owasp_id} foi detectado"
    
    def test_performance_with_large_payload(self, training_system):
        """Testa performance com payload grande"""
        large_payload = "A" * 10000 + "' OR '1'='1" + "B" * 10000
        
        start_time = time.time()
        result = training_system.detect_attack(large_payload)
        end_time = time.time()
        
        assert result['attack_detected'] is True
        owasp_attacks = result.get('owasp_attacks', [])
        assert any("A03" in attack for attack in owasp_attacks)
        assert (end_time - start_time) < 1.0  # Deve ser rápido (< 1 segundo)
    
    def test_multiple_attacks_in_single_payload(self, training_system):
        """Testa detecção de múltiplos ataques em um único payload"""
        multi_attack_payload = "' OR '1'='1 AND <script>alert('XSS')</script> AND ../../../etc/passwd"
        
        result = training_system.detect_attack(multi_attack_payload)
        
        assert result['attack_detected'] is True
        owasp_attacks = result.get('owasp_attacks', [])
        assert len(owasp_attacks) >= 1  # Deve detectar pelo menos 1 tipo de ataque
        
        # Verificar se diferentes tipos foram detectados
        attack_ids = [attack.split(":")[0] for attack in owasp_attacks]
        assert "A01" in attack_ids or "A03" in attack_ids  # Path traversal ou injection
    
    def test_case_insensitive_detection(self, training_system):
        """Testa detecção insensível a maiúsculas/minúsculas"""
        test_cases = [
            ("ADMIN:ADMIN", True),
            ("Admin:Admin", True),
            ("admin:admin", True),
            ("SELECT * FROM users", True),
            ("select * from users", True),
            ("SeLeCt * FrOm UsErS", True)
        ]
        
        for payload, should_detect in test_cases:
            result = training_system.detect_attack(payload)
            assert result['attack_detected'] == should_detect, f"Falha na detecção de: {payload}"
    
    def test_edge_cases(self, training_system):
        """Testa casos extremos"""
        edge_cases = [
            "",  # String vazia
            " ",  # Apenas espaço
            "\n\t\r",  # Apenas caracteres de controle
            "null",  # String null
            "undefined",  # String undefined
            "0",  # Zero
            "false",  # Boolean false como string
        ]
        
        for case in edge_cases:
            result = training_system.detect_attack(case)
            # Casos extremos não devem causar erro, mas podem ou não ser detectados
            assert isinstance(result['attack_detected'], bool)
            assert isinstance(result.get('owasp_attacks', []), list)


class TestOWASPTrainingSystemIntegration:
    """Testes de integração para o sistema de treinamento OWASP"""
    
    def test_full_training_and_detection_cycle(self):
        """Testa ciclo completo de treinamento e detecção"""
        # Usar mocks reais
        mock_abiss = Mock()
        mock_abiss.learn_threat_pattern.return_value = "pattern_123"
        mock_abiss.detect_threat.return_value = {
            'threat_detected': True,
            'confidence': 0.8,
            'patterns': [{'name': 'sql_injection', 'severity': 0.9}]
        }
        mock_nnis = Mock()
        mock_nnis.analyze_network_pattern.return_value = {
            'anomaly_detected': False,
            'confidence': 0.3
        }
        
        system = OWASPTrainingSystem(mock_abiss, mock_nnis)
        
        # 1. Treinar todos os padrões
        training_results = system.train_all_patterns()
        assert all(training_results.values())
        
        # 2. Testar detecção
        test_results = system.test_detection_capabilities()
        assert test_results["success_rate"] > 80  # Pelo menos 80% de sucesso
        
        # 3. Gerar relatório
        report = system.get_training_report()
        assert report["training_stats"]["patterns_trained"] == 10
        
        # 4. Testar bloqueio
        result = system.detect_attack("' OR '1'='1")
        if result['attack_detected']:
            block_result = system.block_attack("' OR '1'='1", result)
            assert block_result["blocked"] is True
    
    def test_system_resilience(self):
        """Testa resiliência do sistema a falhas"""
        # Mock que falha ocasionalmente
        mock_abiss = Mock()
        mock_abiss.learn_threat_pattern.side_effect = ["p1", None, "p3", "p4", None, "p6", "p7", "p8", "p9", "p10"]
        mock_abiss.detect_threat.return_value = {
            'threat_detected': False,
            'confidence': 0.1,
            'patterns': []
        }
        mock_nnis = Mock()
        mock_nnis.analyze_network_pattern.return_value = {
            'anomaly_detected': False,
            'confidence': 0.1
        }
        
        system = OWASPTrainingSystem(mock_abiss, mock_nnis)
        
        # Treinar com algumas falhas
        results = system.train_all_patterns()
        
        # Verificar que o sistema continua funcionando mesmo com falhas
        successful_trainings = sum(results.values())
        assert successful_trainings == 8  # 8 sucessos, 2 falhas
        assert system.training_stats["patterns_trained"] == 8
    
    def test_concurrent_detection(self):
        """Testa detecção concorrente (simulada)"""
        mock_abiss = Mock()
        mock_abiss.learn_threat_pattern.return_value = "pattern_123"
        mock_abiss.detect_threat.return_value = {
            'threat_detected': True,
            'confidence': 0.8,
            'patterns': ['detected_pattern']
        }
        mock_nnis = Mock()
        mock_nnis.analyze_network_pattern.return_value = {
            'anomaly_detected': False,
            'confidence': 0.3
        }
        
        system = OWASPTrainingSystem(mock_abiss, mock_nnis)
        
        # Simular múltiplas detecções simultâneas
        test_payloads = [
            "' OR '1'='1",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd",
            "admin:admin",
            "http://localhost:22"
        ]
        
        results = []
        for payload in test_payloads:
            result = system.detect_attack(payload)
            results.append(result)
        
        # Verificar que todas as detecções funcionaram
        assert all(result['attack_detected'] for result in results)
        assert all(len(result.get('detected_patterns', [])) > 0 for result in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])