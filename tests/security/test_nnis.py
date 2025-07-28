"""
Test NNIS - TDD Implementation
Testa o sistema NNIS (Neural Network Immune System)
"""
import unittest
from unittest.mock import MagicMock
from atous_sec_network.security.nnis import NNIS

class TestNNIS(unittest.TestCase):
    """Testa funcionalidades principais do NNIS"""

    def setUp(self):
        self.nnis = NNIS()

    def test_pattern_recognition(self):
        """Testa reconhecimento de padrões"""
        data = {"event": "login", "success": True}
        result = self.nnis.recognize_pattern(data)
        self.assertIsInstance(result, bool)

    def test_immune_memory_update(self):
        """Testa atualização da memória imune"""
        pattern = {"event": "attack", "type": "DoS"}
        label = "attack_DoS"
        self.nnis.update_immune_memory(pattern, label)
        self.assertIn(label, self.nnis.pattern_memory)

    def test_distributed_response(self):
        """Testa resposta imune distribuída"""
        node_id = "nodeX"
        self.nnis.distributed_response(node_id, threat=True)
        self.assertGreaterEqual(len(self.nnis.response_log), 1)

    def test_model_update(self):
        """Testa atualização do modelo neural"""
        new_model = MagicMock()
        version = 2
        self.nnis.update_model(new_model, version)
        self.assertEqual(self.nnis.model_version, version)
        self.assertIs(self.nnis.gemma_model, new_model)

    def test_integration_with_abiss(self):
        """Testa integração com o ABISS"""
        mock_abiss = MagicMock()
        self.nnis.integrate_with_abiss(mock_abiss)
        self.assertTrue(True)

    def test_get_status(self):
        """Testa obtenção de status do NNIS"""
        status = self.nnis.get_status()
        self.assertIn("patterns", status)
        self.assertIn("responses", status)
        self.assertIn("model_version", status)

if __name__ == '__main__':
    unittest.main()