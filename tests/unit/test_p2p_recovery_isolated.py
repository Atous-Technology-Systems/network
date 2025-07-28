"""
Isolated Test P2P Recovery - TDD Implementation
Testa o sistema de mitigação de churn e recuperação P2P de forma isolada
"""
import unittest
from unittest.mock import Mock, patch, MagicMock, call, ANY
import time
import threading
from typing import Dict, List, Set, Optional, Tuple
import logging

# Configure logging for tests
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import the module we're testing
from atous_sec_network.network.p2p_recovery import ChurnMitigation, NodeHealth

class TestP2PRecoveryIsolated(unittest.TestCase):
    """Testa o sistema de recuperação P2P de forma isolada"""
    
    @classmethod
    def setUpClass(cls):
        """Setup class-level test resources"""
        # Configure test parameters
        cls.HEALTH_CHECK_INTERVAL = 0.5  # Shorter for faster tests
        cls.RECOVERY_TIMEOUT = 1.0
        cls.MONITOR_WAIT = 0.1  # Shorter wait time for tests
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        # Create test nodes
        self.nodes = ["node1", "node2", "node3", "node4", "node5"]
        
        # Patch the threading.Thread to prevent actual thread creation
        self.thread_patcher = patch('threading.Thread', autospec=True)
        self.mock_thread_class = self.thread_patcher.start()
        
        # Configure the mock thread
        self.mock_thread = MagicMock()
        self.mock_thread_class.return_value = self.mock_thread
        
        # Create the mitigator with test parameters
        self.mitigator = ChurnMitigation(
            self.nodes, 
            health_check_interval=self.HEALTH_CHECK_INTERVAL
        )
        self.mitigator.set_recovery_timeout(self.RECOVERY_TIMEOUT)
        
        # Patch time-related functions
        self.time_patcher = patch('time.time')
        self.mock_time = self.time_patcher.start()
        self.mock_time.return_value = 1000.0  # Base time
        
        # Patch sleep to speed up tests
        self.sleep_patcher = patch('time.sleep')
        self.mock_sleep = self.sleep_patcher.start()
        
        # Track monitoring state
        self._monitoring = False
    
    def tearDown(self):
        """Limpeza após cada teste"""
        # Stop all patches
        self.thread_patcher.stop()
        self.time_patcher.stop()
        self.sleep_patcher.stop()
        
        # Stop monitoring if it was started
        if hasattr(self, 'mitigator') and hasattr(self.mitigator, 'stop_health_monitor'):
            self.mitigator.stop_health_monitor()
    
    def test_initial_node_list(self):
        """Testa inicialização da lista de nós"""
        with self.subTest("Check initial node counts"):
            self.assertEqual(len(self.mitigator.active_nodes), 5)
            self.assertEqual(len(self.mitigator.failed_nodes), 0)
            
        with self.subTest("Check specific nodes"):
            self.assertIn("node1", self.mitigator.active_nodes)
            self.assertIn("node5", self.mitigator.active_nodes)
            
        with self.subTest("Check node health initialization"):
            health_status = self.mitigator.get_health_status()
            for node in self.nodes:
                self.assertIn(node, health_status)
                self.assertIsInstance(health_status[node], NodeHealth)
    
    @patch('random.random', return_value=0.06)  # Will make _ping_node return False
    def test_failure_detection(self, mock_random):
        """Testa detecção de falha de nó"""
        # Store initial active nodes
        initial_active = set(self.mitigator.active_nodes)
        
        # Call _handle_node_failure directly since we're testing the failure handling
        failure_time = 1000.0
        self.mock_time.return_value = failure_time
        self.mitigator._handle_node_failure("node3", failure_time)
        
        with self.subTest("Check node failure status"):
            self.assertNotIn("node3", self.mitigator.active_nodes)
            self.assertIn("node3", self.mitigator.failed_nodes)
            self.assertEqual(len(self.mitigator.failed_nodes), 1)
            
        with self.subTest("Check health status update"):
            health = self.mitigator.get_health_status().get("node3")
            self.assertIsNotNone(health)
            self.assertFalse(health.is_active)
            self.assertEqual(health.failure_count, 1)
    
    def test_data_redistribution(self):
        """Testa redistribuição de dados após falha"""
        # Configure test data shards
        self.mitigator.data_shards = {
            "node1": ["shardA1", "shardB1"],
            "node2": ["shardA2", "shardB2"],
            "node3": ["shardA3", "shardB3"],
            "node4": ["shardA4", "shardB4"],
            "node5": ["shardA5", "shardB5"]
        }
        
        # Simulate node3 failure
        self.mitigator.handle_node_failure("node3")
        
        # Check if shards were redistributed
        with self.subTest("Check shard redistribution"):
            # The failed node should have no shards
            self.assertNotIn("node3", self.mitigator.data_shards)
            
            # The shards should be redistributed to other nodes
            all_redistributed_shards = []
            for node, shards in self.mitigator.data_shards.items():
                if node != "node3":
                    all_redistributed_shards.extend(shards)
            
            # All shards should be accounted for
            self.assertIn("shardA3", all_redistributed_shards)
            self.assertIn("shardB3", all_redistributed_shards)
    
    def test_node_recovery(self):
        """Testa recuperação de nó após falha"""
        # Mark node3 as failed
        failure_time = 1000.0
        self.mock_time.return_value = failure_time
        self.mitigator._handle_node_failure("node3", failure_time)
        self.assertIn("node3", self.mitigator.failed_nodes)
        
        # Simulate node3 coming back online
        recovery_time = failure_time + self.RECOVERY_TIMEOUT + 1
        self.mock_time.return_value = recovery_time
        
        # Call recovery check
        self.mitigator._check_node_recovery(recovery_time)
        
        # Node should be back in active nodes
        self.assertIn("node3", self.mitigator.active_nodes)
        self.assertNotIn("node3", self.mitigator.failed_nodes)
        
        # Health status should be updated
        health = self.mitigator.get_health_status().get("node3")
        self.assertIsNotNone(health)
        self.assertTrue(health.is_active)
    
    def test_health_monitor_thread_management(self):
        """Testa gerenciamento da thread de monitoramento"""
        with self.subTest("Start monitoring"):
            self.mitigator.start_health_monitor()
            self.mock_thread_class.assert_called_once()
            self.mock_thread.start.assert_called_once()
            self.assertTrue(self.mitigator._monitor_thread is not None)
        
        with self.subTest("Stop monitoring"):
            self.mitigator.stop_health_monitor()
            self.assertTrue(self.mitigator._stop_event.is_set())
            
            # If we have a mock thread, check that join was called
            if hasattr(self.mitigator, '_monitor_thread') and self.mitigator._monitor_thread:
                self.mitigator._monitor_thread.join.assert_called_once()


    def test_network_partition_detection(self):
        """Testa detecção de partições na rede"""
        # Test with no partitions (all nodes can reach each other)
        with patch.object(self.mitigator, '_can_reach_node', return_value=True):
            partitions = self.mitigator.detect_network_partitions()
            # Should be one partition with all active nodes
            self.assertEqual(len(partitions), 1)
            # Should contain exactly the test nodes we added
            self.assertEqual(len(partitions[0]), len(self.nodes))
            
            # Check that all our test nodes are in the partition
            for node in self.nodes:
                self.assertIn(node, partitions[0])
    
    def test_network_partition_with_isolation(self):
        """Testa detecção de partições quando um nó está isolado"""
        # Create a new mitigator with a smaller set of nodes for this test
        test_nodes = ["node1", "node2", "node3", "node4"]
        
        # Create a mock for _can_reach_node
        def mock_can_reach(source, target):
            # node3 is isolated - can't reach or be reached by any node
            if source == 'node3' or target == 'node3':
                print(f"Mock: {source} cannot reach {target} (node3 is isolated)")
                return False
            # All other nodes can reach each other
            print(f"Mock: {source} can reach {target}")
            return True
        
        # Create a new mitigator with our test nodes
        with patch('random.random', return_value=0.5):  # Make _ping_node return True
            mitigator = ChurnMitigation(test_nodes)
            
            # Patch the _can_reach_node method with our mock
            with patch.object(mitigator, '_can_reach_node', side_effect=mock_can_reach) as mock_method:
                print("\nTesting with node3 isolated...")
                
                # Get the partitions
                partitions = mitigator.detect_network_partitions()
                
                # Debug output
                print(f"Partitions: {partitions}")
                print(f"Number of partitions: {len(partitions)}")
                
                # Check if our mock was called
                self.assertGreater(mock_method.call_count, 0, "_can_reach_node mock was not called")
                
                # We should have exactly 2 partitions (node3 and the rest)
                self.assertEqual(len(partitions), 2, 
                               f"Expected 2 partitions, got {len(partitions)}: {partitions}")
                
                # One partition should contain only node3
                node3_partition = next((p for p in partitions if 'node3' in p), None)
                self.assertIsNotNone(node3_partition, "Node3 should be in one of the partitions")
                self.assertEqual(len(node3_partition), 1, 
                               f"Node3 should be alone in its partition, but got {node3_partition}")
                
                # The other partition should contain the rest of the nodes
                other_partition = next((p for p in partitions if p != node3_partition), None)
                self.assertIsNotNone(other_partition, "Should have a second partition")
                
                # The other partition should have all other test nodes (node1, node2, node4)
                test_node_count = sum(1 for node in test_nodes if node != 'node3' and node in other_partition)
                self.assertEqual(test_node_count, 3, 
                               f"Other partition should have 3 test nodes, but has {test_node_count}")
                
                print("Test passed: Partitions detected correctly")


if __name__ == '__main__':
    unittest.main()
