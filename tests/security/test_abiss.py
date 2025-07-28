"""
Test ABISS - TDD Implementation
Testa o sistema ABISS (Adaptive Behaviour Intelligence Security System)
"""
import unittest
from unittest.mock import MagicMock
from atous_sec_network.security.abiss import ABISS

class TestABISS(unittest.TestCase):
    """Testa funcionalidades principais do ABISS"""

    def setUp(self):
        self.abiss = ABISS()

    def test_behavioral_profiling(self):
        """Testa o perfilamento comportamental de um nó"""
        node_id = "node1"
        data = {"cpu": 10, "mem": 20}
        self.abiss.profile_behavior(node_id, data)
        self.assertIn(node_id, self.abiss.behavior_profiles)

    def test_anomaly_detection(self):
        """Testa detecção de anomalias"""
        node_id = "node2"
        data = {"cpu": 99, "mem": 99}
        result = self.abiss.detect_anomaly(node_id, data)
        self.assertIsInstance(result, bool)

    def test_adaptive_response(self):
        """Testa resposta adaptativa a anomalias"""
        node_id = "node3"
        self.abiss.adaptive_response(node_id, anomaly=True)
        self.assertGreaterEqual(len(self.abiss.response_history), 1)

    def test_integration_with_p2p(self):
        """Testa integração com o gerenciador P2P"""
        mock_p2p = MagicMock()
        self.abiss.integrate_with_p2p(mock_p2p)
        # No exception means pass
        self.assertTrue(True)

    def test_integration_with_ota(self):
        """Testa integração com o sistema OTA"""
        mock_ota = MagicMock()
        self.abiss.integrate_with_ota(mock_ota)
        self.assertTrue(True)

    def test_integration_with_nnis(self):
        """Testa integração com o NNIS"""
        mock_nnis = MagicMock()
        self.abiss.integrate_with_nnis(mock_nnis)
        self.assertTrue(True)

    def test_get_status(self):
        """Testa obtenção de status do ABISS"""
        status = self.abiss.get_status()
        self.assertIn("profiles", status)
        self.assertIn("anomalies", status)
        self.assertIn("responses", status)

if __name__ == '__main__':
    unittest.main()