"""
Test P2P Recovery - TDD Implementation
Testa o sistema de mitigação de churn e recuperação P2P
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import time
import threading
from typing import Dict, List, Set

from atous_sec_network.network.p2p_recovery import ChurnMitigation


class TestP2PRecovery(unittest.TestCase):
    """Testa o sistema de recuperação P2P"""
    
    @classmethod
    def setUpClass(cls):
        """Setup class-level test resources"""
        # Configure longer timeouts for stability
        cls.HEALTH_CHECK_INTERVAL = 2
        cls.RECOVERY_TIMEOUT = 3
        cls.MONITOR_WAIT = 0.5
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        self.nodes = ["node1", "node2", "node3", "node4", "node5"]
        self.mitigator = ChurnMitigation(
            self.nodes, 
            health_check_interval=self.HEALTH_CHECK_INTERVAL
        )
        self.mitigator.set_recovery_timeout(self.RECOVERY_TIMEOUT)
        
        # Set thread safety flags
        self._monitoring = False
    
    def tearDown(self):
        """Limpeza após cada teste"""
        if hasattr(self, 'mitigator'):
            self.mitigator.stop_health_monitor()
            # Wait for monitor thread to fully stop
            if hasattr(self.mitigator, '_monitor_thread') and self.mitigator._monitor_thread:
                if self.mitigator._monitor_thread.is_alive():
                    self.mitigator._monitor_thread.join(timeout=1.0)
                    self.assertFalse(self.mitigator._monitor_thread.is_alive(), 
                                   "Thread de monitoramento não foi encerrada corretamente")
    
    def test_initial_node_list(self):
        """Testa inicialização da lista de nós"""
        with self.subTest("Check initial node counts"):
            self.assertEqual(len(self.mitigator.active_nodes), 5)
            self.assertEqual(len(self.mitigator.failed_nodes), 0)
            
        with self.subTest("Check specific nodes"):
            self.assertIn("node1", self.mitigator.active_nodes)
            self.assertIn("node5", self.mitigator.active_nodes)
            
        with self.subTest("Check node health initialization"):
            for node in self.nodes:
                self.assertIn(node, self.mitigator.get_health_status())
    
    @patch('atous_sec_network.network.p2p_recovery.ChurnMitigation._ping_node')
    def test_failure_detection(self, mock_ping):
        """Testa detecção de falha de nó"""
        # Configure mock to fail for node3
        mock_ping.side_effect = lambda node: node != "node3"
        
        with self.subTest("Start monitoring"):
            self.mitigator.start_health_monitor()
            self._monitoring = True
            
            # Wait for detection
            time.sleep(self.MONITOR_WAIT)
        
        with self.subTest("Check node failure status"):
            self.assertNotIn("node3", self.mitigator.active_nodes)
            self.assertIn("node3", self.mitigator.failed_nodes)
            self.assertEqual(len(self.mitigator.failed_nodes), 1)
            
        with self.subTest("Check health status update"):
            health = self.mitigator.get_health_status().get("node3")
            self.assertIsNotNone(health)
            self.assertFalse(health.is_active)
            self.assertGreater(health.failure_count, 0)
    
    def test_data_redistribution(self):
        """Testa redistribuição de dados após falha"""
        # Configurar shards de dados
        self.mitigator.data_shards = {
            "node1": ["shardA1", "shardB1"],
            "node2": ["shardA2", "shardB2"],
            "node3": ["shardA3", "shardB3"],
            "node4": ["shardA4", "shardB4"],
            "node5": ["shardA5", "shardB5"]
        }
        
        # Simular falha do node3
        self.mitigator.handle_node_failure("node3")
        
        # Verificar se os shards foram redistribuídos
        self.assertNotIn("node3", self.mitigator.data_shards)
        
        # Verificar que os shards foram distribuídos entre os nós restantes
        remaining_nodes = ["node1", "node2", "node4", "node5"]
        total_shards = 0
        for node in remaining_nodes:
            total_shards += len(self.mitigator.data_shards[node])
        
        # Com erasure coding, os shards do nó falhado são redistribuídos para redundância
        # Total esperado: 8 shards originais + 2 shards redistribuídos = 10 shards
        self.assertEqual(total_shards, 10)
        
        # Verificar que todos os nós restantes receberam pelo menos um shard adicional
        for node in remaining_nodes:
            self.assertGreaterEqual(len(self.mitigator.data_shards[node]), 2)
    
    def test_service_reassignment(self):
        """Testa reassignação de serviços após falha"""
        # Configurar serviços
        self.mitigator.service_assignments = {
            "aggregator": "node3",
            "security_monitor": "node2",
            "data_storage": "node1"
        }
        
        # Simular falha do node3
        self.mitigator.handle_node_failure("node3")
        
        # Verificar que o serviço foi reassignado
        self.assertNotEqual(self.mitigator.service_assignments["aggregator"], "node3")
        self.assertIn(self.mitigator.service_assignments["aggregator"], self.mitigator.active_nodes)
        
        # Serviços em nós não falhados devem permanecer
        self.assertEqual(self.mitigator.service_assignments["security_monitor"], "node2")
        self.assertEqual(self.mitigator.service_assignments["data_storage"], "node1")
    
    def test_erasure_coding_redundancy(self):
        """Testa redundância com erasure coding"""
        # Configurar dados com erasure coding
        self.mitigator.data_shards = {
            "node1": ["shardA1", "shardB1", "shardC1"],
            "node2": ["shardA2", "shardB2", "shardC2"],
            "node3": ["shardA3", "shardB3", "shardC3"],
            "node4": ["shardA4", "shardB4", "shardC4"]
        }
        
        # Simular falha de múltiplos nós
        self.mitigator.handle_node_failure("node3")
        self.mitigator.handle_node_failure("node4")
        
        # Verificar que ainda há redundância suficiente
        remaining_nodes = ["node1", "node2"]
        total_shards = 0
        for node in remaining_nodes:
            total_shards += len(self.mitigator.data_shards[node])
        
        # Deve ter pelo menos 6 shards (2 nós * 3 shards cada)
        self.assertGreaterEqual(total_shards, 6)
    
    def test_health_monitor_threading(self):
        """Testa threading do monitor de saúde"""
        # Verificar que o monitor pode ser iniciado e parado
        self.mitigator.start_health_monitor()
        self.assertTrue(self.mitigator._monitor_thread.is_alive())
        
        self.mitigator.stop_health_monitor()
        time.sleep(0.1)  # Pequena pausa para thread parar
        self.assertFalse(self.mitigator._monitor_thread.is_alive())
    
    def test_concurrent_failures(self):
        """Testa tratamento de falhas concorrentes"""
        # Simular múltiplas falhas simultâneas
        failed_nodes = ["node2", "node4"]
        
        for node in failed_nodes:
            self.mitigator.handle_node_failure(node)
        
        # Verificar que todos os nós falhados foram tratados
        for node in failed_nodes:
            self.assertNotIn(node, self.mitigator.active_nodes)
            self.assertIn(node, self.mitigator.failed_nodes)
        
        # Verificar que os serviços foram reassignados corretamente
        self.assertEqual(len(self.mitigator.active_nodes), 3)  # 5 - 2 = 3
    
    def test_recovery_mechanism(self):
        """Testa mecanismo de recuperação de nós"""
        # Reduzir o tempo de timeout para o teste
        original_timeout = self.mitigator.recovery_timeout
        self.mitigator.recovery_timeout = 1  # 1 segundo para o teste
        
        try:
            # Simular falha com timestamp antigo
            old_time = time.time() - 2  # 2 segundos atrás
            self.mitigator._handle_node_failure("node3", old_time)
            self.assertIn("node3", self.mitigator.failed_nodes)
            
            # Simular recuperação - forçar recuperação imediata
            self.mitigator._ping_node = lambda node: True  # Todos os nós respondem
            
            # Forçar verificação de recuperação e executar monitoramento
            current_time = time.time()
            self.mitigator._check_node_recovery(current_time)
            
            # Garantir que o monitoramento contínuo também funciona
            self.mitigator.start_health_monitor()
            time.sleep(0.1)
            self.mitigator.stop_health_monitor()
            
            # Verificar que o nó foi restaurado
            self.assertIn("node3", self.mitigator.active_nodes)
            self.assertNotIn("node3", self.mitigator.failed_nodes)
        finally:
            # Restaurar o timeout original
            self.mitigator.recovery_timeout = original_timeout
    
    def test_load_balancing(self):
        """Testa balanceamento de carga após redistribuição"""
        # Configurar dados desbalanceados
        self.mitigator.data_shards = {
            "node1": ["shard1", "shard2", "shard3", "shard4"],
            "node2": ["shard5"],
            "node3": ["shard6", "shard7"],
            "node4": ["shard8"]
        }
        
        # Simular falha do node1 (mais carregado)
        self.mitigator.handle_node_failure("node1")
        
        # Verificar que a carga foi distribuída
        remaining_nodes = ["node2", "node3", "node4"]
        shard_counts = [len(self.mitigator.data_shards[node]) for node in remaining_nodes]
        
        # Verificar que não há nós sobrecarregados
        max_shards = max(shard_counts)
        min_shards = min(shard_counts)
        
        # A diferença não deve ser muito grande
        self.assertLessEqual(max_shards - min_shards, 2)
    
    def test_network_partition_handling(self):
        """Testa tratamento de partições de rede"""
        # Simular partição de rede (alguns nós isolados)
        def mock_ping(node):
            # node1 e node2 podem se comunicar, node3, node4, node5 formam outra partição
            # Mas para simular uma partição real, alguns nós não respondem
            if node in ["node3", "node4", "node5"]:
                return False  # Nós na partição isolada não respondem
            return True  # Nós na partição principal respondem
        
        self.mitigator._ping_node = mock_ping
        
        # Executar monitoramento
        self.mitigator.start_health_monitor()
        time.sleep(0.1)
        self.mitigator.stop_health_monitor()
        
        # Verificar que os nós isolados foram detectados como falhados
        self.assertNotIn("node3", self.mitigator.active_nodes)
        self.assertNotIn("node4", self.mitigator.active_nodes)
        self.assertNotIn("node5", self.mitigator.active_nodes)
        
        # Verificar que os nós na partição principal ainda estão ativos
        self.assertIn("node1", self.mitigator.active_nodes)
        self.assertIn("node2", self.mitigator.active_nodes)
        
        # Verificar que o número total de nós ativos diminuiu
        self.assertTrue(len(self.mitigator.active_nodes) < 5)
    
    def test_graceful_degradation(self):
        """Testa degradação graciosa do sistema"""
        # Configurar serviços críticos
        self.mitigator.service_assignments = {
            "critical_service": "node1",
            "secondary_service": "node2",
            "backup_service": "node3"
        }
        
        # Simular falhas progressivas
        self.mitigator.handle_node_failure("node3")  # Falha backup
        self.mitigator.handle_node_failure("node2")  # Falha secundário
        
        # Verificar que o serviço crítico ainda está funcionando
        self.assertIn("critical_service", self.mitigator.service_assignments)
        self.assertEqual(self.mitigator.service_assignments["critical_service"], "node1")
        
        # Verificar que serviços secundários foram reassignados
        self.assertIn("secondary_service", self.mitigator.service_assignments)
        self.assertIn("backup_service", self.mitigator.service_assignments)
    
    def test_metrics_collection(self):
        """Testa coleta de métricas de saúde"""
        # Simular algumas falhas
        self.mitigator.handle_node_failure("node3")
        self.mitigator.handle_node_failure("node4")
        
        # Obter métricas
        metrics = self.mitigator.get_health_metrics()
        
        # Verificar métricas básicas
        self.assertIn("active_nodes", metrics)
        self.assertIn("failed_nodes", metrics)
        self.assertIn("uptime", metrics)
        self.assertIn("recovery_rate", metrics)
        
        # Verificar valores
        self.assertEqual(metrics["active_nodes"], 3)
        self.assertEqual(metrics["failed_nodes"], 2)
        self.assertGreaterEqual(metrics["uptime"], 0)
    
    def test_automatic_cleanup(self):
        """Testa limpeza automática de nós falhados antigos"""
        # Adicionar nós falhados com timestamps antigos
        old_timestamp = time.time() - 3600  # 1 hora atrás
        self.mitigator.failed_nodes = {
            "old_node1": old_timestamp,
            "old_node2": old_timestamp,
            "recent_node": time.time() - 60  # 1 minuto atrás
        }
        
        # Executar limpeza
        cleaned_count = self.mitigator._cleanup_old_failures(max_age_minutes=30)
        
        # Verificar que nós antigos foram removidos
        self.assertEqual(cleaned_count, 2)
        self.assertNotIn("old_node1", self.mitigator.failed_nodes)
        self.assertNotIn("old_node2", self.mitigator.failed_nodes)
        self.assertIn("recent_node", self.mitigator.failed_nodes)


class TestP2PNetworkTopology(unittest.TestCase):
    """Testa topologia da rede P2P"""
    
    def setUp(self):
        self.nodes = ["node1", "node2", "node3", "node4", "node5", "node6"]
        self.mitigator = ChurnMitigation(self.nodes, health_check_interval=1)  # Short interval for tests
    
    def tearDown(self):
        """Limpeza após cada teste"""
        if hasattr(self, 'mitigator'):
            self.mitigator.stop_health_monitor()

    
    def test_network_connectivity(self):
        """Testa conectividade da rede"""
        # Verificar que todos os nós estão conectados
        for node in self.nodes:
            self.assertIn(node, self.mitigator.active_nodes)
        
        # Simular falha de nós centrais
        self.mitigator.handle_node_failure("node3")
        self.mitigator.handle_node_failure("node4")
        
        # Verificar que a rede ainda está conectada
        remaining_nodes = ["node1", "node2", "node5", "node6"]
        for node in remaining_nodes:
            self.assertIn(node, self.mitigator.active_nodes)
    
    def test_routing_table_update(self):
        """Testa atualização da tabela de roteamento"""
        # Configurar tabela de roteamento inicial
        self.mitigator.routing_table = {
            "node1": ["node2", "node3"],
            "node2": ["node1", "node4"],
            "node3": ["node1", "node5"],
            "node4": ["node2", "node6"],
            "node5": ["node3", "node6"],
            "node6": ["node4", "node5"]
        }
        
        # Simular falha de node3
        self.mitigator.handle_node_failure("node3")
        
        # Verificar que a tabela foi atualizada
        self.assertNotIn("node3", self.mitigator.routing_table)
        
        # Verificar que rotas para node3 foram removidas
        for routes in self.mitigator.routing_table.values():
            self.assertNotIn("node3", routes)
    
    def test_network_diameter_calculation(self):
        """Testa cálculo do diâmetro da rede"""
        # Configurar rede em anel
        self.mitigator.routing_table = {
            "node1": ["node2", "node6"],
            "node2": ["node1", "node3"],
            "node3": ["node2", "node4"],
            "node4": ["node3", "node5"],
            "node5": ["node4", "node6"],
            "node6": ["node5", "node1"]
        }
        
        # Calcular diâmetro
        diameter = self.mitigator._calculate_network_diameter()
        
        # Em uma rede em anel com 6 nós, o diâmetro deve ser 3
        self.assertEqual(diameter, 3)


class TestP2PSecurity(unittest.TestCase):
    """Testa aspectos de segurança P2P"""
    
    def setUp(self):
        self.nodes = ["node1", "node2", "node3", "node4", "node5"]
        self.mitigator = ChurnMitigation(self.nodes, health_check_interval=1)
    def tearDown(self):
        """Limpeza após cada teste"""
        if hasattr(self, 'mitigator'):
            self.mitigator.stop_health_monitor()
    def test_byzantine_fault_detection(self):
        """Testa detecção de falhas bizantinas"""
        # Simular nó bizantino (responde mas com dados incorretos)
        def mock_ping_byzantine(node):
            if node == "node3":
                return True  # Responde, mas é malicioso
            return True
        
        self.mitigator._ping_node = mock_ping_byzantine
        
        # Configurar dados para verificação
        self.mitigator.data_shards = {
            "node1": ["shardA1"],
            "node2": ["shardA2"],
            "node3": ["shardA3_corrupted"],  # Dados corrompidos
            "node4": ["shardA4"]
        }
        
        # Detectar falha bizantina
        byzantine_nodes = self.mitigator._detect_byzantine_failures()
        
        # Verificar que node3 foi detectado como bizantino
        self.assertIn("node3", byzantine_nodes)
    
    def test_consensus_mechanism(self):
        """Testa mecanismo de consenso para decisões críticas"""
        # Simular decisão que requer consenso
        decision_data = {"action": "redistribute_data", "target_nodes": ["node1", "node2"]}
        
        # Obter consenso
        consensus_reached = self.mitigator._reach_consensus(decision_data, quorum=3)
        
        # Verificar que consenso foi alcançado
        self.assertTrue(consensus_reached)
    
    def test_encrypted_communication(self):
        """Testa comunicação criptografada entre nós"""
        # Simular mensagem criptografada
        message = "sensitive_data"
        encrypted_message = self.mitigator._encrypt_message(message, "node2")
        
        # Verificar que a mensagem foi criptografada
        self.assertNotEqual(encrypted_message, message)
        
        # Simular descriptografia
        decrypted_message = self.mitigator._decrypt_message(encrypted_message, "node2")
        
        # Verificar que a mensagem foi descriptografada corretamente
        self.assertEqual(decrypted_message, message)
    
    def test_network_partition_detection(self):
        """Testa detecção de partição de rede"""
        # Configurar nós em diferentes partições
        partition1 = {"node1", "node2"}
        partition2 = {"node3", "node4", "node5"}
        
        def mock_can_reach(node1, node2):
            if node1 in partition1 and node2 in partition1:
                return True
            if node1 in partition2 and node2 in partition2:
                return True
            return False
        
        with patch.object(self.mitigator, '_can_reach_node', side_effect=mock_can_reach):
            # Executar detecção de partição
            partitions = self.mitigator.detect_network_partitions()
            
            # Debug output
            print("\nDetected partitions:", partitions)
            print("Expected partitions:", [partition1, partition2])
            
            # Verificar que as partições foram detectadas corretamente
            self.assertEqual(len(partitions), 2, f"Expected 2 partitions, got {len(partitions)}: {partitions}")
            
            # Check each expected partition exists in the detected partitions
            found_partition1 = any(p == partition1 for p in partitions)
            found_partition2 = any(p == partition2 for p in partitions)
            
            print(f"Found partition1: {found_partition1}")
            print(f"Found partition2: {found_partition2}")
            
            self.assertTrue(found_partition1, f"Partition {partition1} not found in {partitions}")
            self.assertTrue(found_partition2, f"Partition {partition2} not found in {partitions}")


if __name__ == '__main__':
    unittest.main()