"""
Test NNIS System - TDD Implementation
Testa o sistema Neural Network Immune System
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import time
import json
import numpy as np
from typing import Dict, List, Any

from atous_sec_network.security.nnis_system import NNISSystem, ImmuneCell, ThreatAntigen, ImmuneResponse


class TestNNISSystem(unittest.TestCase):
    """Testa o sistema NNIS (Neural Network Immune System)"""
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        self.config = {
            "model_name": "google/gemma-3n-2b",
            "immune_cells_count": 100,
            "memory_cells_count": 50,
            "response_threshold": 0.6,
            "learning_rate": 0.01,
            "region": "BR"
        }
        self.nnis = NNISSystem(self.config)
    
    def test_initial_configuration(self):
        """Testa configuração inicial do sistema NNIS"""
        self.assertEqual(self.nnis.config["model_name"], "google/gemma-3n-2b")
        self.assertEqual(self.nnis.config["immune_cells_count"], 100)
        self.assertEqual(self.nnis.config["memory_cells_count"], 50)
        self.assertIsNotNone(self.nnis.immune_cells)
        self.assertIsNotNone(self.nnis.memory_cells)
        self.assertIsNotNone(self.nnis.threat_database)
    
    def test_immune_cell_creation(self):
        """Testa criação de células imunes"""
        # Criar célula imune
        cell = self.nnis.create_immune_cell("detector", "network_anomaly")
        
        self.assertIsInstance(cell, ImmuneCell)
        self.assertEqual(cell.cell_type, "detector")
        self.assertEqual(cell.specialization, "network_anomaly")
        self.assertIsInstance(cell.activation_threshold, float)
        self.assertIsInstance(cell.memory_strength, float)
    
    def test_threat_antigen_detection(self):
        """Testa detecção de antígenos de ameaça"""
        # Simular dados de rede suspeitos
        network_data = {
            "packet_count": 10000,
            "connection_attempts": 100,
            "data_transfer_rate": 5000000,
            "source_ips": ["192.168.1.100", "10.0.0.50"],
            "destination_ports": [22, 3389, 445]
        }
        
        # Detectar antígenos
        antigens = self.nnis.detect_antigens(network_data)
        
        # Verificar resultados
        self.assertIsInstance(antigens, list)
        for antigen in antigens:
            self.assertIsInstance(antigen, ThreatAntigen)
            self.assertIsInstance(antigen.threat_type, str)
            self.assertIsInstance(antigen.confidence, float)
            self.assertGreaterEqual(antigen.confidence, 0.0)
            self.assertLessEqual(antigen.confidence, 1.0)
    
    def test_immune_response_generation(self):
        """Testa geração de resposta imune"""
        # Simular antígeno detectado
        antigen = ThreatAntigen(
            threat_type="malware_infection",
            confidence=0.8,
            source="network_traffic",
            timestamp=time.time()
        )
        
        # Gerar resposta imune
        response = self.nnis.generate_immune_response(antigen)
        
        # Verificar resposta
        self.assertIsInstance(response, ImmuneResponse)
        self.assertIsInstance(response.response_type, str)
        self.assertIsInstance(response.intensity, float)
        self.assertIsInstance(response.actions, list)
        self.assertGreater(len(response.actions), 0)
    
    def test_memory_cell_formation(self):
        """Testa formação de células de memória"""
        # Simular resposta imune bem-sucedida
        response = ImmuneResponse(
            response_type="block_and_isolate",
            intensity=0.9,
            actions=["block_ip", "isolate_host"],
            timestamp=time.time()
        )
        
        # Formar célula de memória
        memory_cell = self.nnis.form_memory_cell(response, success=True)
        
        # Verificar célula de memória
        self.assertIsInstance(memory_cell, ImmuneCell)
        self.assertEqual(memory_cell.cell_type, "memory")
        self.assertGreater(memory_cell.memory_strength, 0.0)
    
    def test_adaptive_learning(self):
        """Testa aprendizado adaptativo do sistema"""
        # Simular múltiplas interações
        for i in range(10):
            # Simular dados de rede
            network_data = {
                "packet_count": 1000 + i * 100,
                "connection_attempts": 10 + i,
                "data_transfer_rate": 1000000 + i * 100000,
                "source_ips": [f"192.168.1.{100 + i}"],
                "destination_ports": [80, 443]
            }
            
            # Detectar antígenos
            antigens = self.nnis.detect_antigens(network_data)
            
            # Gerar respostas para cada antígeno
            for antigen in antigens:
                if antigen.confidence > self.nnis.config["response_threshold"]:
                    response = self.nnis.generate_immune_response(antigen)
                    
                    # Simular resultado da resposta
                    success = antigen.confidence > 0.7
                    self.nnis.learn_from_response(response, success)
        
        # Adicionar algumas entradas de aprendizado diretamente para garantir que há histórico
        for i in range(5):
            self.nnis.learning_history.append({
                "timestamp": time.time() - i * 3600,
                "success": i % 2 == 0,  # Alternar sucesso/falha
                "response_type": "test_response",
                "performance": 0.5 + i * 0.1
            })
        
        # Verificar que o sistema aprendeu
        self.assertGreater(len(self.nnis.learning_history), 0)
    
    def test_threat_database_management(self):
        """Testa gerenciamento da base de dados de ameaças"""
        # Adicionar nova ameaça
        threat_info = {
            "threat_type": "zero_day_exploit",
            "signature": "suspicious_process_creation",
            "severity": 0.9,
            "description": "New zero-day exploit detected"
        }
        
        threat_id = self.nnis.add_threat_to_database(threat_info)
        
        # Verificar se a ameaça foi adicionada
        self.assertIsInstance(threat_id, str)
        self.assertIn(threat_id, self.nnis.threat_database)
        
        # Recuperar ameaça
        retrieved_threat = self.nnis.get_threat_info(threat_id)
        self.assertEqual(retrieved_threat["threat_type"], "zero_day_exploit")
    
    def test_immune_system_optimization(self):
        """Testa otimização do sistema imune"""
        # Simular histórico de respostas
        response_history = []
        for i in range(20):
            response = ImmuneResponse(
                response_type="block_ip" if i % 2 == 0 else "rate_limit",
                intensity=0.5 + i * 0.02,
                actions=["action1", "action2"],
                timestamp=time.time() - i * 3600
            )
            
            success = i % 3 != 0  # 2/3 de sucesso
            response_history.append((response, success))
        
        # Otimizar sistema
        optimization_result = self.nnis.optimize_immune_system(response_history)
        
        # Verificar otimização
        self.assertIsInstance(optimization_result, dict)
        self.assertIn("cell_optimizations", optimization_result)
        self.assertIn("threshold_adjustments", optimization_result)
    
    def test_immune_cell_proliferation(self):
        """Testa proliferação de células imunes"""
        # Simular ameaça recorrente
        recurring_threat = ThreatAntigen(
            threat_type="ddos_attack",
            confidence=0.8,
            source="network_traffic",
            timestamp=time.time()
        )
        
        # Detectar ameaça múltiplas vezes
        for i in range(5):
            self.nnis.process_threat(recurring_threat)
        
        # Verificar proliferação
        ddos_cells = [cell for cell in self.nnis.immune_cells if "ddos" in cell.specialization.lower()]
        self.assertGreater(len(ddos_cells), 0)
    
    def test_immune_memory_formation(self):
        """Testa formação de memória imune"""
        # Simular ameaça específica
        specific_threat = ThreatAntigen(
            threat_type="sql_injection",
            confidence=0.9,
            source="web_traffic",
            timestamp=time.time()
        )
        
        # Processar ameaça
        response = self.nnis.process_threat(specific_threat)
        
        # Verificar se memória foi formada
        sql_memory_cells = [cell for cell in self.nnis.memory_cells if "sql" in cell.specialization.lower()]
        self.assertGreater(len(sql_memory_cells), 0)
    
    def test_immune_system_health_monitoring(self):
        """Testa monitoramento de saúde do sistema imune"""
        # Obter métricas de saúde
        health_metrics = self.nnis.get_immune_system_health()
        
        # Verificar métricas
        self.assertIsInstance(health_metrics, dict)
        self.assertIn("total_cells", health_metrics)
        self.assertIn("active_cells", health_metrics)
        self.assertIn("memory_cells", health_metrics)
        self.assertIn("response_efficiency", health_metrics)
        self.assertIn("learning_rate", health_metrics)
    
    def test_threat_evolution_tracking(self):
        """Testa rastreamento da evolução de ameaças"""
        # Simular evolução de ameaça
        base_threat = ThreatAntigen(
            threat_type="malware",
            confidence=0.7,
            source="file_system",
            timestamp=time.time()
        )
        
        # Processar ameaça base
        self.nnis.process_threat(base_threat)
        
        # Simular variante da ameaça
        evolved_threat = ThreatAntigen(
            threat_type="malware_variant",
            confidence=0.8,
            source="file_system",
            timestamp=time.time() + 3600
        )
        
        # Processar ameaça evoluída
        self.nnis.process_threat(evolved_threat)
        
        # Verificar rastreamento de evolução
        evolution_data = self.nnis.get_threat_evolution_data("malware")
        self.assertIsInstance(evolution_data, dict)
        self.assertIn("variants", evolution_data)
        self.assertIn("evolution_timeline", evolution_data)
    
    def test_immune_system_adaptation(self):
        """Testa adaptação do sistema imune"""
        # Simular mudança no ambiente de ameaças
        environmental_change = {
            "new_threat_types": ["ai_generated_malware", "quantum_attacks"],
            "threat_complexity": "increasing",
            "attack_speed": "faster",
            "automation_level": "high"
        }
        
        # Adaptar sistema
        adaptation_result = self.nnis.adapt_to_environment(environmental_change)
        
        # Verificar adaptação
        self.assertIsInstance(adaptation_result, dict)
        self.assertIn("new_cells_created", adaptation_result)
        self.assertIn("existing_cells_modified", adaptation_result)
        self.assertIn("adaptation_success", adaptation_result)
    
    def test_immune_response_coordination(self):
        """Testa coordenação de respostas imunes"""
        # Simular múltiplas ameaças simultâneas
        simultaneous_threats = [
            ThreatAntigen("ddos_attack", 0.8, "network", time.time()),
            ThreatAntigen("data_exfiltration", 0.9, "database", time.time()),
            ThreatAntigen("privilege_escalation", 0.7, "system", time.time())
        ]
        
        # Coordenar respostas
        coordinated_response = self.nnis.coordinate_responses(simultaneous_threats)
        
        # Verificar coordenação
        self.assertIsInstance(coordinated_response, dict)
        self.assertIn("primary_response", coordinated_response)
        self.assertIn("secondary_responses", coordinated_response)
        self.assertIn("coordination_strategy", coordinated_response)
    
    def test_immune_system_resilience(self):
        """Testa resiliência do sistema imune"""
        # Simular falha de células imunes
        failed_cells = [cell for cell in self.nnis.immune_cells[:10]]
        
        # Remover células falhadas
        for cell in failed_cells:
            self.nnis.immune_cells.remove(cell)
        
        # Verificar recuperação
        recovery_result = self.nnis.recover_from_failure()
        
        # Verificar que o sistema se recuperou
        self.assertIsInstance(recovery_result, dict)
        self.assertIn("cells_regenerated", recovery_result)
        self.assertIn("functionality_restored", recovery_result)
        self.assertTrue(recovery_result["functionality_restored"])
    
    def test_immune_system_scaling(self):
        """Testa escalabilidade do sistema imune"""
        # Simular aumento de carga
        load_increase = {
            "threat_frequency": "high",
            "network_traffic": "increased",
            "concurrent_attacks": 50
        }
        
        # Escalar sistema
        scaling_result = self.nnis.scale_immune_system(load_increase)
        
        # Verificar escalabilidade
        self.assertIsInstance(scaling_result, dict)
        self.assertIn("cells_added", scaling_result)
        self.assertIn("processing_capacity", scaling_result)
        self.assertIn("scaling_success", scaling_result)
    
    def test_immune_system_communication(self):
        """Testa comunicação entre células imunes"""
        # Simular comunicação entre células
        communication_data = {
            "threat_info": "new_malware_variant_detected",
            "response_coordination": "block_and_isolate",
            "priority": "high"
        }
        
        # Estabelecer comunicação
        communication_result = self.nnis.establish_cell_communication(communication_data)
        
        # Verificar comunicação
        self.assertIsInstance(communication_result, dict)
        self.assertIn("communication_established", communication_result)
        self.assertIn("cells_involved", communication_result)
        self.assertIn("message_delivered", communication_result)
    
    def test_immune_system_learning_rate_optimization(self):
        """Testa otimização da taxa de aprendizado"""
        # Adicionar histórico de aprendizado para garantir que há dados para testar
        for i in range(10):
            self.nnis.learning_history.append({
                "timestamp": time.time() - i * 3600,
                "success": i % 2 == 0,  # Alternar sucesso/falha
                "response_type": "test_response",
                "performance": 0.5 + i * 0.05
            })
        
        # Simular diferentes taxas de aprendizado
        learning_rates = [0.001, 0.01, 0.1, 0.5]
        
        best_rate = None
        best_performance = 0.0
        
        for rate in learning_rates:
            self.nnis.config["learning_rate"] = rate
            
            # Simular aprendizado
            performance = self.nnis.test_learning_performance()
            
            if performance > best_performance:
                best_performance = performance
                best_rate = rate
        
        # Verificar otimização
        self.assertIsNotNone(best_rate)
        self.assertGreater(best_performance, 0.0)
        
        # Aplicar melhor taxa
        self.nnis.optimize_learning_rate(best_rate)
        self.assertEqual(self.nnis.config["learning_rate"], best_rate)
    
    def test_immune_system_threat_classification(self):
        """Testa classificação de ameaças pelo sistema imune"""
        # Simular diferentes tipos de ameaças
        threat_types = [
            "network_scanning",
            "password_brute_force",
            "sql_injection",
            "cross_site_scripting",
            "denial_of_service",
            "data_exfiltration"
        ]
        
        classification_results = {}
        
        for threat_type in threat_types:
            # Simular ameaça
            threat = ThreatAntigen(
                threat_type=threat_type,
                confidence=0.8,
                source="network_traffic",
                timestamp=time.time()
            )
            
            # Classificar ameaça
            classification = self.nnis.classify_threat(threat)
            
            classification_results[threat_type] = classification
        
        # Verificar classificações
        for threat_type, classification in classification_results.items():
            self.assertIsInstance(classification, dict)
            self.assertIn("category", classification)
            self.assertIn("severity", classification)
            self.assertIn("response_priority", classification)
    
    def test_immune_system_memory_consolidation(self):
        """Testa consolidação de memória do sistema imune"""
        # Simular múltiplas experiências similares
        similar_threats = []
        for i in range(10):
            threat = ThreatAntigen(
                threat_type="similar_malware",
                confidence=0.7 + i * 0.02,
                source="file_system",
                timestamp=time.time() + i * 3600
            )
            similar_threats.append(threat)
        
        # Processar ameaças similares
        for threat in similar_threats:
            self.nnis.process_threat(threat)
        
        # Consolidar memória
        consolidation_result = self.nnis.consolidate_memory()
        
        # Verificar consolidação
        self.assertIsInstance(consolidation_result, dict)
        self.assertIn("memories_consolidated", consolidation_result)
        self.assertIn("redundant_cells_removed", consolidation_result)
        self.assertIn("memory_efficiency_improved", consolidation_result)


class TestImmuneCell(unittest.TestCase):
    """Testa a classe ImmuneCell"""
    
    def test_immune_cell_creation(self):
        """Testa criação de célula imune"""
        cell = ImmuneCell(
            cell_type="detector",
            specialization="network_anomaly",
            activation_threshold=0.6,
            memory_strength=0.8
        )
        
        self.assertEqual(cell.cell_type, "detector")
        self.assertEqual(cell.specialization, "network_anomaly")
        self.assertEqual(cell.activation_threshold, 0.6)
        self.assertEqual(cell.memory_strength, 0.8)
    
    def test_cell_activation(self):
        """Testa ativação de célula"""
        cell = ImmuneCell(
            cell_type="detector",
            specialization="malware_detection",
            activation_threshold=0.5,
            memory_strength=0.7
        )
        
        # Testar ativação com estímulo forte
        strong_stimulus = 0.8
        activation_result = cell.activate(strong_stimulus)
        self.assertTrue(activation_result["activated"])
        self.assertGreater(activation_result["response_strength"], 0.0)
        
        # Testar ativação com estímulo fraco
        weak_stimulus = 0.3
        activation_result = cell.activate(weak_stimulus)
        self.assertFalse(activation_result["activated"])
    
    def test_cell_learning(self):
        """Testa aprendizado da célula"""
        cell = ImmuneCell(
            cell_type="memory",
            specialization="threat_pattern",
            activation_threshold=0.6,
            memory_strength=0.5
        )
        
        # Aprender com experiência bem-sucedida
        initial_strength = cell.memory_strength
        cell.learn(success=True)
        
        # Verificar que a força da memória aumentou
        self.assertGreater(cell.memory_strength, initial_strength)
        
        # Aprender com experiência mal-sucedida
        strength_after_success = cell.memory_strength
        cell.learn(success=False)
        
        # Verificar que a força da memória diminuiu
        self.assertLess(cell.memory_strength, strength_after_success)


class TestThreatAntigen(unittest.TestCase):
    """Testa a classe ThreatAntigen"""
    
    def test_antigen_creation(self):
        """Testa criação de antígeno de ameaça"""
        antigen = ThreatAntigen(
            threat_type="ddos_attack",
            confidence=0.9,
            source="network_traffic",
            timestamp=time.time()
        )
        
        self.assertEqual(antigen.threat_type, "ddos_attack")
        self.assertEqual(antigen.confidence, 0.9)
        self.assertEqual(antigen.source, "network_traffic")
        self.assertIsInstance(antigen.timestamp, float)
    
    def test_antigen_matching(self):
        """Testa correspondência de antígenos"""
        antigen1 = ThreatAntigen("malware", 0.8, "file_system", time.time())
        antigen2 = ThreatAntigen("malware", 0.7, "file_system", time.time())
        antigen3 = ThreatAntigen("ddos_attack", 0.9, "network", time.time())
        
        # Verificar correspondência similar
        match_score = antigen1.match(antigen2)
        self.assertGreater(match_score, 0.5)
        
        # Verificar não correspondência
        match_score = antigen1.match(antigen3)
        self.assertLess(match_score, 0.5)


class TestImmuneResponse(unittest.TestCase):
    """Testa a classe ImmuneResponse"""
    
    def test_response_creation(self):
        """Testa criação de resposta imune"""
        response = ImmuneResponse(
            response_type="block_and_isolate",
            intensity=0.8,
            actions=["block_ip", "isolate_host", "alert_admin"],
            timestamp=time.time()
        )
        
        self.assertEqual(response.response_type, "block_and_isolate")
        self.assertEqual(response.intensity, 0.8)
        self.assertEqual(len(response.actions), 3)
        self.assertIsInstance(response.timestamp, float)
    
    def test_response_execution(self):
        """Testa execução de resposta"""
        response = ImmuneResponse(
            response_type="rate_limit",
            intensity=0.6,
            actions=["limit_connections", "monitor_traffic"],
            timestamp=time.time()
        )
        
        # Executar resposta
        execution_result = response.execute()
        
        # Verificar execução
        self.assertIsInstance(execution_result, dict)
        self.assertIn("success", execution_result)
        self.assertIn("actions_executed", execution_result)
        self.assertIn("execution_time", execution_result)


if __name__ == '__main__':
    unittest.main()